package gofortify

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

func RemoveBearer(token *string) {
	*token = strings.TrimSpace(*token)
	splitToken := strings.SplitN(*token, " ", 2)
	if len(splitToken) == 2 && splitToken[0] == "Bearer" {
		*token = splitToken[1]
	}
}

func GetIncidentTime() (int64, error) {
	incidentTime := GetBlacklist().Get(Config.IncidentKey)
	now := time.Now().Unix()

	//it's mean incident time is not set
	if incidentTime == nil {
		GetBlacklist().Set(Config.IncidentKey, now, 0)
		return now, errors.New("incident time not set")
	}

	incidentTimeUnix, ok := incidentTime.(int64)
	if !ok {
		incidentTimeUnixString, ok := incidentTime.(string)
		if !ok {
			GetBlacklist().Delete(Config.IncidentKey)
			GetBlacklist().Set(Config.IncidentKey, now, 0)
			return now, errors.New("incident time is not int64")
		}

		incidentTimeUnix, err := strconv.ParseInt(incidentTimeUnixString, 10, 64)
		if err != nil {
			GetBlacklist().Delete(Config.IncidentKey)
			GetBlacklist().Set(Config.IncidentKey, now, 0)
			return now, errors.New("failed to parse incident time")
		}

		return incidentTimeUnix, nil
	}

	return incidentTimeUnix, nil
}

func BlacklistToken(payload *Payload) {
	ttl := time.Until(time.Unix(payload.EXP, 0))
	GetBlacklist().Set(payload.JTI, true, ttl)
}

func BlacklistTokenAndPairToken(payload *Payload) {
	ttl := time.Until(time.Unix(payload.EXP, 0))
	GetBlacklist().Set(payload.JTI, true, ttl)
	GetBlacklist().Set(payload.PTI, true, ttl)
}
