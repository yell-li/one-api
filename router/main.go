package router

import (
	"github.com/gin-gonic/gin"
)

func SetRouter(router *gin.Engine) {
	SetApiRouter(router)
	SetDashboardRouter(router)
	SetRelayRouter(router)
}

//
//func SetRouter(router *gin.Engine, buildFS embed.FS, indexPage []byte) {
//	SetApiRouter(router)
//	SetDashboardRouter(router)
//	SetRelayRouter(router)
//	frontendBaseUrl := os.Getenv("FRONTEND_BASE_URL")
//	if common.IsMasterNode && frontendBaseUrl != "" {
//		frontendBaseUrl = ""
//		common.SysLog("FRONTEND_BASE_URL is ignored on master node")
//	}
//	if frontendBaseUrl == "" {
//		SetWebRouter(router, buildFS, indexPage)
//	} else {
//		frontendBaseUrl = strings.TrimSuffix(frontendBaseUrl, "/")
//		router.NoRoute(func(c *gin.Context) {
//			c.Redirect(http.StatusMovedPermanently, fmt.Sprintf("%s%s", frontendBaseUrl, c.Request.RequestURI))
//		})
//	}
//}
