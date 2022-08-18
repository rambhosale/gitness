// Copyright 2021 Harness Inc. All rights reserved.
// Use of this source code is governed by the Polyform Free Trial License
// that can be found in the LICENSE.md file for this repository.

package cli

import (
	"encoding/json"
	"io/ioutil"

	"github.com/harness/scm/cli/util"
	"github.com/harness/scm/client"
	"gopkg.in/alecthomas/kingpin.v2"
)

type registerCommand struct {
	server string
}

func (c *registerCommand) run(*kingpin.ParseContext) error {
	username, password := util.Credentials()
	client := client.New(c.server)
	token, err := client.Register(username, password)
	if err != nil {
		return err
	}
	path, err := util.Config()
	if err != nil {
		return err
	}
	token.Address = c.server
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}

// helper function to register the register command.
func registerRegister(app *kingpin.Application) {
	c := new(registerCommand)

	cmd := app.Command("register", "register a user").
		Action(c.run)

	cmd.Arg("server", "server address").
		Default("http://localhost:3000").
		StringVar(&c.server)
}
