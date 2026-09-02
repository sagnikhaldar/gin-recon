package gin

import "path"

// JoinPaths replicates gin-gonic/gin's own routergroup.go joinPaths exactly
// (verified against github.com/gin-gonic/gin@v1.10.0's utils.go): group path
// composition has a specific trailing-slash rule that plain path.Join does
// not preserve, and route identity depends on getting it byte-for-byte
// right, not just "close enough."
func JoinPaths(absolutePath, relativePath string) string {
	if relativePath == "" {
		return absolutePath
	}
	finalPath := path.Join(absolutePath, relativePath)
	if lastChar(relativePath) == '/' && lastChar(finalPath) != '/' {
		return finalPath + "/"
	}
	return finalPath
}

func lastChar(s string) byte {
	if s == "" {
		panic("gin.lastChar: empty string")
	}
	return s[len(s)-1]
}
