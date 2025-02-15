/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"

	math3 "github.com/IBM/mathlib"
	idemix2 "github.com/hyperledger-labs/fabric-smart-client/platform/fabric/core/generic/msp/idemix"
	driver2 "github.com/hyperledger-labs/fabric-smart-client/platform/fabric/driver"
	view2 "github.com/hyperledger-labs/fabric-smart-client/platform/view"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/flogging"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/hash"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/kvs"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/view"
	config2 "github.com/hyperledger-labs/fabric-token-sdk/token/core/config"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/identity/msp/common"
	"github.com/hyperledger-labs/fabric-token-sdk/token/driver"
	"github.com/hyperledger-labs/fabric-token-sdk/token/driver/config"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
)

var logger = flogging.MustGetLogger("token-sdk.msp.idemix")

type PublicParametersWithIdemixSupport interface {
	IdemixCurve() math3.CurveID
}

type LocalMembership struct {
	sp                     view2.ServiceProvider
	configManager          config.Manager
	defaultNetworkIdentity view.Identity
	signerService          common.SignerService
	binderService          common.BinderService
	deserializerManager    common.DeserializerManager
	kvs                    common.KVS
	mspID                  string
	cacheSize              int

	resolversMutex          sync.RWMutex
	resolvers               []*common.Resolver
	resolversByName         map[string]*common.Resolver
	resolversByEnrollmentID map[string]*common.Resolver
	curveID                 math3.CurveID
	identities              []*config.Identity
}

func NewLocalMembership(
	sp view2.ServiceProvider,
	configManager config.Manager,
	defaultNetworkIdentity view.Identity,
	signerService common.SignerService,
	binderService common.BinderService,
	deserializerManager common.DeserializerManager,
	kvs common.KVS,
	mspID string,
	cacheSize int,
	curveID math3.CurveID,
	identities []*config.Identity,
) *LocalMembership {
	return &LocalMembership{
		sp:                      sp,
		configManager:           configManager,
		defaultNetworkIdentity:  defaultNetworkIdentity,
		signerService:           signerService,
		binderService:           binderService,
		deserializerManager:     deserializerManager,
		kvs:                     kvs,
		mspID:                   mspID,
		cacheSize:               cacheSize,
		resolversByEnrollmentID: map[string]*common.Resolver{},
		resolversByName:         map[string]*common.Resolver{},
		curveID:                 curveID,
		identities:              identities,
	}
}

func (lm *LocalMembership) DefaultNetworkIdentity() view.Identity {
	return lm.defaultNetworkIdentity
}

func (lm *LocalMembership) IsMe(id view.Identity) bool {
	return lm.signerService.IsMe(id)
}

func (lm *LocalMembership) GetIdentifier(id view.Identity) (string, error) {
	lm.resolversMutex.RLock()
	defer lm.resolversMutex.RUnlock()

	label := string(id)
	if logger.IsEnabledFor(zapcore.DebugLevel) {
		logger.Debugf("get anonymous identity info by label [%s]", hash.Hashable(label))
	}
	r := lm.getResolver(label)
	if r == nil {
		if logger.IsEnabledFor(zapcore.DebugLevel) {
			logger.Debugf("anonymous identity info not found for label [%s][%v]", hash.Hashable(label), lm.resolversByName)
		}
		return "", errors.New("not found")
	}
	return r.Name, nil
}

func (lm *LocalMembership) GetDefaultIdentifier() string {
	for _, resolver := range lm.resolvers {
		if resolver.Default {
			return resolver.Name
		}
	}
	return ""
}

func (lm *LocalMembership) GetIdentityInfo(label string, auditInfo []byte) (driver.IdentityInfo, error) {
	lm.resolversMutex.RLock()
	defer lm.resolversMutex.RUnlock()

	if logger.IsEnabledFor(zapcore.DebugLevel) {
		logger.Debugf("get anonymous identity info by label [%s]", hash.Hashable(label))
	}
	r := lm.getResolver(label)
	if r == nil {
		return nil, errors.Errorf("anonymous identity info not found for label [%s][%v]", hash.Hashable(label), lm.resolversByName)
	}

	return common.NewIdentityInfo(
		r.Name,
		r.EnrollmentID,
		func() (view.Identity, []byte, error) {
			return r.GetIdentity(&driver2.IdentityOptions{
				EIDExtension: true,
				AuditInfo:    auditInfo,
			})
		},
	), nil
}

func (lm *LocalMembership) RegisterIdentity(id string, path string) error {
	lm.resolversMutex.Lock()
	defer lm.resolversMutex.Unlock()

	if err := lm.storeEntryInKVS(id, path); err != nil {
		return err
	}
	return lm.registerIdentity(id, path, lm.GetDefaultIdentifier() == "", lm.curveID)
}

func (lm *LocalMembership) IDs() ([]string, error) {
	var ids []string
	for _, resolver := range lm.resolvers {
		ids = append(ids, resolver.Name)
	}
	return ids, nil
}

func (lm *LocalMembership) Reload(pp driver.PublicParameters) error {
	logger.Debugf("Reload Idemix Wallets for [%+q]", lm.identities)
	idemixPP, ok := pp.(PublicParametersWithIdemixSupport)
	if !ok {
		return errors.Errorf("public params do not support idemix")
	}
	// set curve id from the public parameters
	lm.curveID = idemixPP.IdemixCurve()

	logger.Debugf("Load Idemix Wallets with the respect to curve [%d], [%+q]", lm.curveID, lm.identities)

	lm.resolversMutex.Lock()
	defer lm.resolversMutex.Unlock()

	// cleanup all resolvers
	lm.resolvers = make([]*common.Resolver, 0)
	lm.resolversByName = make(map[string]*common.Resolver)
	lm.resolversByEnrollmentID = make(map[string]*common.Resolver)

	// load identities from configuration
	for _, identityConfig := range lm.identities {
		logger.Debugf("load wallet for identity [%+v]", identityConfig)
		if err := lm.registerIdentity(identityConfig.ID, identityConfig.Path, identityConfig.Default, lm.curveID); err != nil {
			return errors.WithMessage(err, "failed to load identity")
		}
		logger.Debugf("load wallet for identity [%+v] done.", identityConfig)
	}

	// load identity from KVS
	logger.Debugf("load identity from KVS")
	if err := lm.loadFromKVS(); err != nil {
		return errors.Wrapf(err, "failed to load identity from KVS")
	}
	logger.Debugf("load identity from KVS done")

	// if no default identity, use the first one
	defaultIdentifier := lm.GetDefaultIdentifier()
	if len(defaultIdentifier) == 0 {
		logger.Warnf("no default identity, use the first one available")
		if len(lm.resolvers) > 0 {
			logger.Warnf("set default identity to %s", lm.resolvers[0].Name)
			lm.resolvers[0].Default = true
		} else {
			logger.Warnf("cannot set default identity, no identity available")
		}
	} else {
		logger.Debugf("default identifier is [%s]", defaultIdentifier)
	}

	return nil
}

func (lm *LocalMembership) registerIdentity(id string, path string, setDefault bool, curveID math3.CurveID) error {
	// Try to register the MSP provider
	translatedPath := lm.configManager.TranslatePath(path)
	if err := lm.registerMSPProvider(id, translatedPath, curveID, setDefault); err != nil {
		logger.Warnf("failed to load idemix msp provider at [%s]:[%s] [%s]", translatedPath, err, debug.Stack())
		// Does path correspond to a holder containing multiple MSP identities?
		if err := lm.registerMSPProviders(translatedPath, curveID); err != nil {
			return errors.WithMessage(err, "failed to register MSP provider")
		}
	}
	return nil
}

func (lm *LocalMembership) registerMSPProvider(id, translatedPath string, curveID math3.CurveID, setDefault bool) error {
	conf, err := idemix2.GetLocalMspConfigWithType(translatedPath, nil, lm.mspID)
	if err != nil {
		logger.Debugf("failed reading idemix msp configuration from [%s]: [%s], try adding 'msp'...", translatedPath, err)
		// Try with "msp"
		conf, err = idemix2.GetLocalMspConfigWithType(filepath.Join(translatedPath, "msp"), nil, lm.mspID)
		if err != nil {
			return errors.Wrapf(err, "failed reading idemix msp configuration from [%s] and with 'msp'", translatedPath)
		}
	}
	// TODO: remove the need for ServiceProvider
	cryptoProvider, err := NewKVSBCCSP(kvs.GetService(lm.sp), curveID)
	if err != nil {
		return errors.WithMessage(err, "failed to instantiate crypto provider")
	}
	provider, err := idemix2.NewProvider(conf, idemix2.GetSignerService(lm.sp), idemix2.Any, cryptoProvider)
	if err != nil {
		return errors.Wrapf(err, "failed instantiating idemix msp provider from [%s]", translatedPath)
	}

	cacheSize, err := lm.cacheSizeForID(id)
	if err != nil {
		return err
	}

	lm.deserializerManager.AddDeserializer(provider)
	lm.addResolver(id, provider.EnrollmentID(), setDefault, NewIdentityCache(provider.Identity, cacheSize).Identity)
	logger.Debugf("added idemix resolver for id %s with cache of size %d", id+"@"+provider.EnrollmentID(), cacheSize)
	return nil
}

func (lm *LocalMembership) registerMSPProviders(translatedPath string, curveID math3.CurveID) error {
	entries, err := os.ReadDir(translatedPath)
	if err != nil {
		logger.Warnf("failed reading from [%s]: [%s]", translatedPath, err)
		return nil
	}
	found := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		if err := lm.registerMSPProvider(id, filepath.Join(translatedPath, id), curveID, false); err != nil {
			logger.Errorf("failed registering msp provider [%s]: [%s]", id, err)
			continue
		}
		found++
	}
	if found == 0 {
		return errors.Errorf("no valid identities found in [%s]", translatedPath)
	}
	return nil
}

func (lm *LocalMembership) addResolver(Name string, EnrollmentID string, defaultID bool, IdentityGetter common.GetIdentityFunc) {
	resolver := &common.Resolver{
		Name:         Name,
		Default:      defaultID,
		EnrollmentID: EnrollmentID,
		GetIdentity:  IdentityGetter,
	}
	lm.resolversByName[Name] = resolver
	if len(EnrollmentID) != 0 {
		lm.resolversByEnrollmentID[EnrollmentID] = resolver
	}
	lm.resolvers = append(lm.resolvers, resolver)
}

func (lm *LocalMembership) getResolver(label string) *common.Resolver {
	if logger.IsEnabledFor(zapcore.DebugLevel) {
		logger.Debugf("get anonymous identity info by label [%s]", hash.Hashable(label))
	}
	r, ok := lm.resolversByName[label]
	if ok {
		return r
	}

	if logger.IsEnabledFor(zapcore.DebugLevel) {
		logger.Debugf("anonymous identity info not found for label [%s][%v]", hash.Hashable(label), lm.resolversByName)
	}
	return nil
}

func (lm *LocalMembership) cacheSizeForID(id string) (int, error) {
	tmss, err := config2.NewTokenSDK(view2.GetConfigService(lm.sp)).GetTMSs()
	if err != nil {
		return 0, errors.WithMessage(err, "failed to obtain token management system instances")
	}

	for _, tms := range tmss {
		for _, owner := range tms.TMS().Wallets.Owners {
			if owner.ID == id {
				logger.Debugf("Cache size for %s is set to be %d", id, owner.CacheSize)
				return owner.CacheSize, nil
			}
		}
	}

	logger.Debugf("cache size for %s not configured, using default (%d)", id, lm.cacheSize)

	return lm.cacheSize, nil
}

func (lm *LocalMembership) storeEntryInKVS(id string, path string) error {
	k, err := kvs.CreateCompositeKey("token-sdk", []string{"msp", "idemix", "registeredIdentity", id})
	if err != nil {
		return errors.Wrapf(err, "failed to create identity key")
	}
	return lm.kvs.Put(k, path)
}

func (lm *LocalMembership) loadFromKVS() error {
	it, err := lm.kvs.GetByPartialCompositeID("token-sdk", []string{"msp", "idemix", "registeredIdentity"})
	if err != nil {
		return errors.WithMessage(err, "failed to get registered identities from kvs")
	}
	defer it.Close()
	for it.HasNext() {
		var path string
		k, err := it.Next(&path)
		if err != nil {
			return errors.WithMessagef(err, "failed to get next registered identities from kvs")
		}

		_, attrs, err := kvs.SplitCompositeKey(k)
		if err != nil {
			return errors.WithMessagef(err, "failed to split key [%s]", k)
		}

		id := attrs[3]
		if lm.getResolver(id) != nil {
			continue
		}

		if err := lm.registerIdentity(id, path, lm.GetDefaultIdentifier() == "", lm.curveID); err != nil {
			return err
		}
	}
	return nil
}
