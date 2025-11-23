package command

type Code int32
type Type int32

type Error interface {
	error
	Code() Code
	Type() Type
}

const (
	ValidationError Type = iota
	ExecuteError
)

type Group int32

const (
	Common Group = 1000

	DIDExchange Group = 2000

	Messaging Group = 3000

	VDR Group = 4000

	ROUTE Group = 5000

	VC Group = 6000

	KMS Group = 7000

	IssueCredential Group = 8000

	PresentProof Group = 9000

	Introduce Group = 10000

	Outofband Group = 11000

	Outofband2 Group = 11100

	VCWallet Group = 12000

	RFC0593 Group = 13000

	LD Group = 14000

	Connection Group = 15000

	LegacyConnection Group = 16000
)

type CommandError struct {
	error
	code    Code
	errType Type
}

func (c *CommandError) Code() Code {
	return c.code
}

func (c *CommandError) Type() Type {
	return c.errType
}

var _ Error = (*CommandError)(nil)

func NewValidationError(code Code, err error) Error {
	return &CommandError{
		error:   err,
		code:    code,
		errType: ValidationError,
	}
}

func NewExecuteError(code Code, err error) Error {
	return &CommandError{
		error:   err,
		code:    code,
		errType: ExecuteError,
	}
}
