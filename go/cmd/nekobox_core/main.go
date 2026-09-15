package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	_ "unsafe"

	"grpc_server"

	happ "nekobox_core/happ"

	"github.com/matsuridayo/libneko/neko_common"
	boxmain "github.com/sagernet/sing-box/cmd/sing-box"
	"github.com/sagernet/sing-box/constant"
)

// happDecryptCli implements `nekobox_core happ-decrypt <link>`: decrypt one
// happ://crypt link and print a single-line JSON result. The Qt GUI calls it
// as a short-lived subprocess, so the output must not contain anything else.
func happDecryptCli(args []string) {
	link := strings.TrimSpace(strings.Join(args, ""))
	if link == "" {
		b, _ := io.ReadAll(os.Stdin)
		link = strings.TrimSpace(string(b))
	}

	type out struct {
		Ok     bool   `json:"ok"`
		Result string `json:"result,omitempty"`
		Error  string `json:"error,omitempty"`
	}

	var result out
	if !happ.IsHappLink(link) {
		result = out{Error: "not a happ://crypt link"}
	} else if decrypted, err := happ.Decrypt(link); err != nil {
		result = out{Error: err.Error()}
	} else {
		result = out{Ok: true, Result: decrypted}
	}

	_ = json.NewEncoder(os.Stdout).Encode(result)
	if !result.Ok {
		os.Exit(1)
	}
}

func main() {
	// happ link decryptor
	if len(os.Args) > 1 && os.Args[1] == "happ-decrypt" {
		happDecryptCli(os.Args[2:])
		return
	}

	fmt.Println("sing-box:", constant.Version, "NekoBox:", neko_common.Version_neko)
	fmt.Println()

	// nekobox_core
	if len(os.Args) > 1 && os.Args[1] == "nekobox" {
		neko_common.RunMode = neko_common.RunMode_NekoBox_Core
		grpc_server.RunCore(setupCore, &server{})
		return
	}

	// sing-box
	boxmain.Main()
}
