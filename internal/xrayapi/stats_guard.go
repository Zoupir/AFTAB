package xrayapi

import "errors"

// A missing stats record is not a zero counter. A new idle user can be
// sampled later. Do not call the metering delta calculator on incomplete data.
func validateTrafficCompleteness(uplinkFound, downlinkFound bool) error {
	if !uplinkFound || !downlinkFound {
		return errors.New("incomplete Xray user traffic sample")
	}
	return nil
}
