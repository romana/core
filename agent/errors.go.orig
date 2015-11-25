package agent

import (
	"fmt"
)

// Error codes.
const (
	EcodeDefault              = 100
	EcodeShelloutFailed       = 101
	EcodeRequestParsingFailed = 102
	EcodeCreateRouteFailed    = 103
)

// ErrorMessages provides description for error codes ErrorMessages[Ecode]string.
var ErrorMessages = map[int]string{
	EcodeDefault:              "Unspecified error",
	EcodeShelloutFailed:       "External command unsuccessful",
	EcodeRequestParsingFailed: "Garbage in the request",
	EcodeCreateRouteFailed:    "Can't create IP route",
}

// Error is a structure that represents error.
type Error struct {
	ErrorCode int
	Message   string
	Cause     string
}

// NewError helps to construct new Error structure.
func NewError(ecode int, cause string) Error {
	return Error{
		ErrorCode: ecode,
		Message:   ErrorMessages[ecode],
		Cause:     cause,
	}
}

// Error is a method to satisfy error interface.
func (e Error) Error() string {
	return e.Message + " (" + e.Cause + ")"
}

func shelloutError(err error, cmd string, args []string) error {
	return NewError(EcodeShelloutFailed, fmt.Sprintf("%v %v: %v", cmd, args, err))
}

func garbageRequestError(key string) error {
	return NewError(EcodeRequestParsingFailed, key)
}

func requestParseError(fields int) error {
	return NewError(EcodeRequestParsingFailed, fmt.Sprintf("number of parsed fields: %v", fields))
}

func netIfRouteCreateError(err error, netif NetIf) error {
	return NewError(EcodeCreateRouteFailed, fmt.Sprintf("target %v: cause %v", netif, err))
}

func routeCreateError(err error, ip string, mask string, dest string) error {
	return NewError(EcodeCreateRouteFailed, fmt.Sprintf("target %s/%s -> %s: cause %v", ip, mask, dest, err))
}

func agentError(err error) error {
	return NewError(EcodeDefault, fmt.Sprintf("Agent: %v", err))
}

func agentErrorString(str string) error {
	return NewError(EcodeDefault, fmt.Sprintf("Agent: %s", str))
}

func ensureLineError(err error) error {
	return NewError(EcodeShelloutFailed, fmt.Sprintf("Failed to provision static lease: %v", err))
}

func noSuchRouteError() error {
	return NewError(EcodeShelloutFailed, fmt.Sprintf("ERROR: No such route"))
}

func wrongHostError() error {
	return NewError(EcodeDefault, fmt.Sprintf("ERROR: Can't resolve internal IP's. It looks like we're running on the host outside of pani config"))
}

func failedToParseOtherHosts(s string) error {
	return NewError(EcodeDefault, fmt.Sprintf("ERROR: Failed to parse netmask out of %s in CreateInterhostRoutes", s))
}

func combinedError(s string, err error) error {
	// TODO scheduled for deprecation, all calls must be refactored
	// to analize incoming errorCode and produce new Error instead
	return fmt.Errorf("%s %s", s, err)
}

func failedToParseNetif() error {
	return NewError(EcodeRequestParsingFailed, fmt.Sprintf("ERROR: Failed to parse netif"))
}
