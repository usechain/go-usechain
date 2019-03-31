package ca

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/usechain/go-usechain/core/types"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/node"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type wizard struct {
	filename string
	info     *types.UserData
	in       *bufio.Reader
}

func MakeWizard(filename string) *wizard {
	return &wizard{
		filename: filename,
		info:     new(types.UserData),
		in:       bufio.NewReader(os.Stdin),
	}
}

func (w *wizard) Run() {
	fmt.Println("+--------------------------------------------------------------------------+")
	fmt.Println("| Welcome to usechain, the first mirror identity blockchain                |")
	fmt.Println("|                                                                          |")
	fmt.Println("| This command lets you create a new identity to registered                |")
	fmt.Println("| e.g ./build/bin/used verify  // create your new json info file           |")
	fmt.Println("| e.g ./build/bin/used --info=<json info file> --photo=<photo1;photo2>     |")
	fmt.Println("+--------------------------------------------------------------------------+")
	w.MakeUserInfo()
}

func (w *wizard) MakeUserInfo() {

	fmt.Println()
	fmt.Println("Which certificate do you use for registered?")
	fmt.Println(" 1. IDCard")
	fmt.Println(" 2. Others")

	choice := w.readString()
	switch {
	case choice == "1":
		w.info.CertType = "1"
		fmt.Println()
		fmt.Println("What is your ID number?")
		w.info.Id = w.readString()

		fmt.Println()
		fmt.Println("What is your name?")
		w.info.Name = w.readString()

		fmt.Println()
		fmt.Println("What is your gender?")
		fmt.Println(" 0. Male")
		fmt.Println(" 1. Female")
		fmt.Println(" 2. Others")
		w.info.Sex = w.readString()

		fmt.Println()
		fmt.Println("What is your country? Please refer to https://en.wikipedia.org/wiki/ISO_3166-1")
		w.info.Nation = w.readString()

		fmt.Println()
		fmt.Println("What is your address? (optional)")
		w.info.Addr = w.readDefaultString("")

		// TODO: will uncomment those code after update credit register API
		// fmt.Println()
		// if w.filename == "" {
		// 	fmt.Println("Please specify a file name to store your information.")
		// 	for {
		// 		w.filename = w.readString()
		// 		if !strings.Contains(w.filename, " ") && !strings.Contains(w.filename, "-") {
		// 			fmt.Printf("\nNow the file name is set to %s.json!\n\n", w.filename)
		// 			break
		// 		}
		// 		log.Error("I also like to live dangerously, still no spaces or hyphens")
		// 	}
		// }

		w.filename = "userData"
		fmt.Printf("\nNow the file name is set to %s.json!\n\n", w.filename)

		out, _ := json.MarshalIndent(w.info, "", "  ")
		if err := ioutil.WriteFile(filepath.Join(node.DefaultDataDir(), fmt.Sprintf("%s.json", w.filename)), out, 0644); err != nil {
			log.Error("Failed to save user info file", "err", err)
		}
		log.Info("Exported user info")

	case choice == "2":
		fmt.Println("We will support other types of documents in the near future.")
	}
}

// readString reads a single line from stdin, trimming if from spaces, enforcing
// non-emptyness.
func (w *wizard) readString() string {
	for {
		fmt.Printf("> ")
		text, err := w.in.ReadString('\n')
		if err != nil {
			log.Crit("Failed to read user input", "err", err)
		}
		if text = strings.TrimSpace(text); text != "" {
			return text
		}
	}
}

// readDefaultString reads a single line from stdin, trimming if from spaces. If
// an empty line is entered, the default value is returned.
func (w *wizard) readDefaultString(def string) string {
	fmt.Printf("> ")
	text, err := w.in.ReadString('\n')
	if err != nil {
		log.Crit("Failed to read user input", "err", err)
	}
	if text = strings.TrimSpace(text); text != "" {
		return text
	}
	return def
}
