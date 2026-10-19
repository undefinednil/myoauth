package handler

import (
	"encoding/json"
	"log"
	"net/http"
)

type commonResp struct {
	Ok  bool   `json:"ok"`
	Msg string `json:"msg"`
}

func responseJson(w http.ResponseWriter, data any, statusCodes ...int) {
	code := http.StatusOK
	w.Header().Set("Content-Type", "application/json")
	if len(statusCodes) > 0 {
		code = statusCodes[0]
	}
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("responseJson encode error: %v\n", err)
	}
}

func responseOk(w http.ResponseWriter) {
	responseJson(w, commonResp{
		Ok:  true,
		Msg: "ok",
	})
}

// responseErrStatus returns a JSON error with an explicit HTTP status code. It
// keeps the {"ok":false,"msg":...} body shape (so the SPA's ApiError renders
// the message) while letting callers use the correct status: 401 for failed
// authentication, 403 for a rejected invitation, 404 for a missing resource and
// 409 for a duplicate.
func responseErrStatus(w http.ResponseWriter, msg string, status int) {
	responseJson(w, commonResp{
		Ok:  false,
		Msg: msg,
	}, status)
}

func responseInputError(w http.ResponseWriter, errs ...error) {
	msg := "input error"
	if len(errs) > 0 {
		msg = errs[0].Error()
	}
	responseJson(w, commonResp{
		Ok:  false,
		Msg: msg,
	}, http.StatusBadRequest)
}

func responseInternalError(w http.ResponseWriter, logger interface{ Println(any ...interface{}) }, err error) {
	logger.Println("internal error:", err)
	responseJson(w, commonResp{
		Ok:  false,
		Msg: "internal error",
	}, http.StatusInternalServerError)
}

func genOkResponse() commonResp {
	return commonResp{
		Ok:  true,
		Msg: "ok",
	}
}

// hasControlChars reports whether s contains any ASCII control character
// (< 0x20 or DEL). Such names could break response headers downstream, so they
// are rejected at registration (FIX B).
func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
