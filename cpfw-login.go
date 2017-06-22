package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
	"github.com/keybase/go-keychain"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	agent     = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/41.0.2272.76 Chrome/41.0.2272.76 Safari/537.36"
	success   = "SUCCESS"
	auth_fail = "AUTH_FAILURE"
)

type LoginResponse struct {
	Context         string
	Type            string
	Opaque          string
	NextStateId     string
	OrgUrl          string
	keepAliveActive bool
	delayInterval   string
}

type LoginParamsRaw struct {
	M          string
	E          string
	LoginToken string
}

type LoginParams struct {
	PublicKey  rsa.PublicKey
	LoginToken string
}

type Attributes struct {
	CheckStatus        bool
	Authenticated      bool
	AgreementVerified  bool
	AgentConnected     bool
	OrgUrl             string
	AgentOsSupported   bool
	AgentRequired      bool
	TimeToEndOfSession int
	TextToEndOfSession string
	KeepaliveRequired  bool
	KeepaliveInterval  int
}

func (r *LoginResponse) String() string {
	return r.Type
}

func (a *Attributes) String() string {
	return fmt.Sprintf("authenticated: %v, end of session: %s", a.Authenticated, a.TextToEndOfSession)
}

func NewLoginParamsRaw(params []byte) (LoginParamsRaw, error) {
	var lpr LoginParamsRaw
	err := json.Unmarshal(params, &lpr)
	return lpr, err
}

func NewLoginParams(params LoginParamsRaw) (*LoginParams, error) {
	m := new(big.Int)
	m.SetString(params.M, 16)
	e, err := strconv.ParseInt(params.E, 16, 0)
	if err != nil {
		return nil, err
	}
	return &LoginParams{rsa.PublicKey{m, int(e)}, params.LoginToken}, nil
}

func login(client *http.Client, uri, user, password string, params *LoginParams) (*LoginResponse, error) {
	crypted_password, err := encrypt(rand.Reader, *params, password)
	if err != nil {
		log.Printf("Error encrypting password: %v", err)
		return nil, err
	}

	response, err := sendPassword(client, uri, user, crypted_password)
	if err != nil {
		log.Printf("Error sending login data: %v", err)
		return nil, err
	}

	if response.Type == auth_fail {
		log.Print("Invalid username/password")
		return nil, err
	}
	if response.Type != success {
		log.Printf("Error logging in: %s", *response)
		return nil, err
	}
	log.Printf("Logged in as %s", user)
	return response, nil
}

func postLogin(client *http.Client, uri string) (*Attributes, error) {
	_, err := fetch(client, uri, "/connect/GetStateAndView")
	if err != nil {
		log.Printf("Error loading post login page: %v", err)
		return nil, err
	}
	attr, err := fetchAttributes(client, uri)
	if err != nil {
		log.Printf("Error loading attributes: %v", err)
		return nil, err
	}
	return attr, nil
}

func checkConnection(client *http.Client, uri string) error {
	_, err := fetch(client, uri, "")
	if err != nil {
		log.Printf("Unable to reach %s: %v", uri, err)
		return err
	}
	log.Printf("Reached %s sucessfully", uri)
	return nil
}

func run(client *http.Client, uri, user, password, check string) error {
	if len(check) == 0 || checkConnection(client, check) != nil {
		lp, err := fetchLoginParams(client, uri)
		if err != nil {
			return err
		}
		_, err = login(client, uri, user, password, lp)
		if err != nil {
			log.Printf("Login failed: %v", err)
			return err
		}
		attr, err := postLogin(client, uri)
		if err != nil {
			log.Printf("Post login failed: %v", err)
			return err
		}
		if attr.TimeToEndOfSession > 0 {
			log.Printf("End of session: %s", attr.TextToEndOfSession)
		} else {
			return errors.New(fmt.Sprintf("Session setup failed: %v", attr))
		}

		if len(check) > 0 {
			return checkConnection(client, check)
		}
	}
	return nil
}

func main() {
	var url string
	var user string
	var password string
	var checkUrl string
	var interval uint
	var insecure bool
	var osx_save_password bool
	var prompt_password bool
	flag.StringVar(&url, "url", os.Getenv("CPFW_AUTH_URL"), "login form base url, also: CPFW_AUTH_URL")
	flag.StringVar(&user, "user", os.Getenv("CPFW_AUTH_USER"), "login username, also: CPFW_AUTH_USER")
	flag.StringVar(&password, "password", os.Getenv("CPFW_AUTH_PASSWORD"), "login password, also: CPFW_AUTH_PASSWORD")
	flag.StringVar(&checkUrl, "check", os.Getenv("CPFW_AUTH_CHECK_URL"), "check url for successful login, also: CPFW_AUTH_CHECK_URL")
	flag.UintVar(&interval, "interval", 0, "recheck connection every Xs")
	flag.BoolVar(&insecure, "insecure", false, "don't verify SSL/TLS connections")
	flag.BoolVar(&osx_save_password, "osx-save-password", false, "save login password in keychain?")
	flag.BoolVar(&prompt_password, "prompt-password", false, "read password from standard input")
	flag.Parse()

	if len(url) == 0 {
		log.Println("Missing mandatory parameter: url")
		os.Exit(1)
	}
	if len(user) == 0 {
		log.Println("Missing mandatory parameter: user")
		os.Exit(1)
	}
	if prompt_password {
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(0)
		if err == nil {
			password = string(bytePassword)
			fmt.Println("\nPassword typed: " + string(bytePassword))
		} else {
			log.Printf("Unexpected error reading password!")
			os.Exit(1)
		}
	}
	if len(password) == 0 {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(url)
		query.SetAccount(user)
		query.SetMatchLimit(keychain.MatchLimitOne)
		query.SetReturnData(true)
		results, err := keychain.QueryItem(query)
		if err != nil || len(results) != 1 {
			// Not found
		} else {
			log.Println("Using password from the keychain.")
			password = string(results[0].Data)
		}

		if err != nil || len(password) == 0 {
			log.Println("No password saved in the keychain.")
			log.Println("Missing mandatory parameter: password")
			os.Exit(1)
		}
	}

	log.Printf("Connecting to: %s", url)

	client := httpClient(url, user, insecure)
	for {
		err := run(client, url, user, password, checkUrl)
		if interval <= 0 {
			// exit loop when not looping
			if err != nil {
				log.Printf("unexpected error: %v", err)
				os.Exit(1)
			}
			break
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
	if (osx_save_password) {
		log.Println("Saving password into keychain...")
		item := keychain.NewItem()
		item.SetSecClass(keychain.SecClassGenericPassword)
		item.SetService(url)
		item.SetAccount(user)
		item.SetData([]byte(password))
		item.SetSynchronizable(keychain.SynchronizableNo)
		item.SetAccessible(keychain.AccessibleWhenUnlocked)

		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(url)
		query.SetAccount(user)
		query.SetMatchLimit(keychain.MatchLimitOne)
		query.SetReturnData(true)

		if keychain.AddItem(item) != nil {
			log.Println("Error adding new password item in the keychain. Bug?")
			os.Exit(1)
		} else if keychain.AddItem(item) == keychain.ErrorDuplicateItem {
			if keychain.UpdateItem(query, item) != nil {
				log.Println("Error updating password in the keychain. Bug?")
				os.Exit(1)
			}
		}
		log.Println("Saved password in the keychain. You don't need --password flag anymore.")
	}
}
