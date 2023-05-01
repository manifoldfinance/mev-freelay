// Copyright (c) 2023 Manifold Finance, Inc.
// The Universal Permissive License (UPL), Version 1.0
// Subject to the condition set forth below, permission is hereby granted to any person obtaining a copy of this software, associated documentation and/or data (collectively the “Software”), free of charge and under any and all copyright rights in the Software, and any and all patent rights owned or freely licensable by each licensor hereunder covering either (i) the unmodified Software as contributed to or provided by such licensor, or (ii) the Larger Works (as defined below), to deal in both
// (a) the Software, and
// (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if one is included with the Software (each a “Larger Work” to which the Software is contributed by such licensors),
// without restriction, including without limitation the rights to copy, create derivative works of, display, perform, and distribute the Software and make, use, sell, offer for sale, import, export, have made, and have sold the Software and the Larger Work(s), and to sublicense the foregoing rights on either these or other terms.
// This license is subject to the following condition:
// The above copyright notice and either this complete permission notice or at a minimum a reference to the UPL must be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// This script ensures source code files have copyright license headers. See license.sh for more information.
package freelay

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/params"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/manifoldfinance/mev-freelay/logger"
)

type RelayConfig struct {
	SecretKey                   *bls.SecretKey
	PublicKey                   *types.PublicKey
	DomainBuilder               types.Domain
	DomainBeaconProposerCapella types.Domain
	GenesisForkVersion          string
	GenesisValidatorsRoot       string
	ForkVersionCapella          string
	ChainID                     uint64

	BlockSimURL     string
	BlockSimURLSafe string
	Network         string
}

func NewRelayConfig(network, url string, pk *types.PublicKey, sk *bls.SecretKey) (*RelayConfig, error) {
	var genesisForkVersion, genesisValidatorsRoot, forkVersionCapella string
	var chainID uint64

	switch network {
	case "main", "mainnet":
		genesisForkVersion = types.GenesisForkVersionMainnet
		genesisValidatorsRoot = types.GenesisValidatorsRootMainnet
		forkVersionCapella = CapellaForkVersionMainnet
		chainID = params.MainnetChainConfig.ChainID.Uint64()
	case "goerli":
		genesisForkVersion = types.GenesisForkVersionGoerli
		genesisValidatorsRoot = types.GenesisValidatorsRootGoerli
		forkVersionCapella = CapellaForkVersionGoerli
		chainID = params.GoerliChainConfig.ChainID.Uint64()
	default:
		return nil, ErrUnknownNetwork
	}

	domainBuilder, err := computeDomain(types.DomainTypeAppBuilder, genesisForkVersion, types.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerCapella, err := computeDomain(types.DomainTypeBeaconProposer, forkVersionCapella, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	logger.Info("running on network", "network", network)
	return &RelayConfig{
		PublicKey:                   pk,
		SecretKey:                   sk,
		DomainBuilder:               domainBuilder,
		DomainBeaconProposerCapella: domainBeaconProposerCapella,
		GenesisForkVersion:          genesisForkVersion,
		GenesisValidatorsRoot:       genesisValidatorsRoot,
		ForkVersionCapella:          forkVersionCapella,
		BlockSimURL:                 url,
		BlockSimURLSafe:             hideCredentialsFromURL(url),
		Network:                     network,
		ChainID:                     chainID,
	}, nil
}

func computeDomain(domainType types.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain types.Domain, err error) {
	genesisValidatorsRoot := types.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, ErrInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return types.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}
