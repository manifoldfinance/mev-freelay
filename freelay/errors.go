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

import "errors"

var (
	ErrNoData                               = errors.New("no data")
	ErrInvalidKey                           = errors.New("invalid key")
	ErrUnknownValidatorByIndx               = errors.New("unknown validator by index")
	ErrInvalidForkVersion                   = errors.New("invalid fork version")
	ErrPayloadNil                           = errors.New("payload is nil")
	ErrReqNil                               = errors.New("request is nil")
	ErrSecretKeyNil                         = errors.New("secret key is nil")
	ErrNoBeaconSynced                       = errors.New("no beacon is synced")
	ErrAllBeaconsFailedGetProposerDuties    = errors.New("all beacons failed to get proposer duties")
	ErrAllBeaconsFailedGetRandao            = errors.New("all beacons failed to get randao")
	ErrAllBeaconsFailedPublishBlock         = errors.New("all beacons failed to publish block")
	ErrSlotCursorConflict                   = errors.New("slot and cursor cannot be used together")
	ErrProposerLimit                        = errors.New("limit cannot be greater than 500")
	ErrUnknownNetwork                       = errors.New("unknown network")
	ErrNoArchivePayloadsFound               = errors.New("no payloads found")
	ErrBestBidNotFound                      = errors.New("best bid not found")
	ErrBidTraceExpired                      = errors.New("bid trace expired")
	ErrBestBidExpired                       = errors.New("best bid expired")
	ErrAllBeaconsFailedGetForkSchedule      = errors.New("all beacons failed to get fork schedule")
	ErrAllBeaconsFailedGetWithdrawals       = errors.New("all beacons failed to get withdrawals")
	ErrAllBeaconsFailedGetValidators        = errors.New("all beacons failed to get validators")
	ErrEmpty                                = errors.New("empty")
	ErrInvalidPayloadSimulate               = errors.New("invalid payload to use for simulation")
	ErrBlockBroadcastedButFailedIntegration = errors.New("block broadcasted but failed to integrate")
	ErrAllBeaconsFailedGetBlockBySlot       = errors.New("all beacons failed to get block by slot")
	ErrMismatchPayloads                     = errors.New("mismatch payloads")
	ErrMismatchHeaders                      = errors.New("mismatch headers")
	ErrNoPayloads                           = errors.New("no payloads")
	ErrValidatorChanRegsFull                = errors.New("validator channel registrations full")
	ErrValidatorTimestampTooFarInTheFuture  = errors.New("validator timestamp too far in the future")
	ErrValidatorTimestampTooFarInThePast    = errors.New("validator timestamp too far in the past")
	ErrValidatorUnknown                     = errors.New("validator unknown")
	ErrMissedBlock                          = errors.New("missed block")
	ErrShutdownInProgress                   = errors.New("shutdown in progress")
)
