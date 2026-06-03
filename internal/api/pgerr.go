package api

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
)

func writePgErr(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		msg := "duplicate value"
		switch pg.ConstraintName {
		case "policies_name_key":
			msg = "policy name already exists — use another name or update the existing policy"
		case "roles_name_key":
			msg = "role name already exists"
		default:
			msg = "duplicate key: " + pg.ConstraintName
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": msg})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}
