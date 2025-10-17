package gofortify

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/iqbalatma/gofortify/blacklist"
	"github.com/iqbalatma/gofortify/config"
)

func RemoveBearer(token *string) {
	*token = strings.TrimSpace(*token)
	splitToken := strings.SplitN(*token, " ", 2)
	if len(splitToken) == 2 && splitToken[0] == "Bearer" {
		*token = splitToken[1]
	}
}

func GetIncidentTime() (int64, error) {
	incidentTime := blacklist.GetBlacklist().Get(config.Config.IncidentKey)
	now := time.Now().Unix()

	if incidentTime == nil { //it's mean incident time is not set
		blacklist.GetBlacklist().Set(config.Config.IncidentKey, now, 0)
		return now, errors.New("incident time not set")
	}
	incidentTimeUnix, ok := incidentTime.(int64)
	if !ok {
		incidentTimeUnixString, ok := incidentTime.(string)
		if !ok {
			blacklist.GetBlacklist().Delete(config.Config.IncidentKey)
			blacklist.GetBlacklist().Set(config.Config.IncidentKey, now, 0)
			return now, errors.New("incident time is not int64")
		}

		incidentTimeUnix, err := strconv.ParseInt(incidentTimeUnixString, 10, 64)
		if err != nil {
			blacklist.GetBlacklist().Delete(config.Config.IncidentKey)
			blacklist.GetBlacklist().Set(config.Config.IncidentKey, now, 0)
			return now, errors.New("failed to parse incident time")
		}

		return incidentTimeUnix, nil
	}

	return incidentTimeUnix, nil
}
