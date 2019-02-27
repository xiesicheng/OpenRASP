//Copyright 2017-2019 Baidu Inc.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http: //www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.


package api

import (
	"fmt"
	"net/http"
	"rasp-cloud/controllers"
	"rasp-cloud/models"
)

type ReportController struct {
	controllers.BaseController
}

var (
	intervals = [...]string{"hour", "day", "month"}
)

// @router /dashboard [post]
func (o *ReportController) Search() {
	var query map[string]interface{}
	o.UnMarshalJson(&query)
	startTimeParam := query["start_time"]
	if startTimeParam == nil {
		o.ServeError(http.StatusBadRequest, "start_time cannot be empty")
	}
	startTime, ok := startTimeParam.(float64)
	if !ok {
		o.ServeError(http.StatusBadRequest, "start_time must be number")
	}
	endTimeParam := query["end_time"]
	if endTimeParam == nil {
		o.ServeError(http.StatusBadRequest, "end_time cannot be empty")
	}
	endTime, ok := endTimeParam.(float64)
	if !ok {
		o.ServeError(http.StatusBadRequest, "end_time must be number")
	}
	intervalParam := query["interval"]
	if intervalParam == nil {
		o.ServeError(http.StatusBadRequest, "interval cannot be empty")
	}
	interval, ok := intervalParam.(string)
	if !ok {
		o.ServeError(http.StatusBadRequest, "interval must be string")
	}
	timeZoneParam := query["time_zone"]
	if timeZoneParam == nil {
		o.ServeError(http.StatusBadRequest, "time_zone cannot be empty")
	}
	timeZone, ok := timeZoneParam.(string)
	if !ok {
		o.ServeError(http.StatusBadRequest, "time_zone must be string")
	}
	isValidInterval := false
	for index := range intervals {
		if interval == intervals[index] {
			isValidInterval = true
		}
	}
	if !isValidInterval {
		o.ServeError(http.StatusBadRequest, "the interval must be in"+fmt.Sprintf("%v", intervals))
	}
	appIdParam := query["app_id"]
	if appIdParam == nil {
		appIdParam = "*"
	}
	appId, ok := appIdParam.(string)
	if !ok {
		o.ServeError(http.StatusBadRequest, "app_id must be string")
	}
	_, err := models.GetAppById(appId)
	if err != nil {
		o.ServeError(http.StatusBadRequest, "failed to get app", err)
	}
	err, result := models.GetHistoryRequestSum(int64(startTime), int64(endTime), interval, timeZone, appId)
	if err != nil {
		o.ServeError(http.StatusBadRequest, "failed to get request sum form ES", err)
	}
	o.Serve(result)

}
