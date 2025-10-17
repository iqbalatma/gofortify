package gofortify

type JWTSubject interface {
	GetSubjectKey() string
}
