//go:generate solc --overwrite --abi --bin nft/nft.sol -o nft/build/
//go:generate abigen --abi nft/build/SampleNFT.abi --bin nft/build/SampleNFT.bin --pkg nft --type SampleNFT --out nft/nft.go

package main

import (
	"log"
	"fmt"
	"os"
	"time"
	"flag"
	"regexp"
	"strings"
	"context"
	"net/http"
	"html/template"
	"database/sql"
	"math/big"
	"io/ioutil"
	"strconv"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gorilla/sessions"
	"github.com/shomali11/util/xhashes"
	"github.com/serg666/ethereumapp/nft"
	_ "github.com/mattn/go-sqlite3"
)

type Page struct {
	Title   string
	Account *Account
	Asset   *Asset
	Token   *Token
	Chunks  []interface{}
}

type Asset struct {
	Id          string
	Name        string
	Description string
	Content     []byte
	ContentType string
}

type Token struct {
	Id int64
}

type Account struct {
	Id    string
	Email string
}

type HistoryResult struct {
	Time      time.Time
	Sender    string
	Recipient string
	Gas       *big.Float
	GasPrice  *big.Float
	Block     uint64
	TxHash    string
	Value     float64
}

type Transaction struct {
	From  string
	To    string
	Value string
}

type Participant struct {
	Id     int64
	Email  string
	Passwd string
}

var (
	err error
	dataDir *string
	baseAccount *string
	contractAddress *string
	sqliteDatabase *sql.DB
	rpcClient *rpc.Client
	ethClient *ethclient.Client
	token *nft.SampleNFT
	chainID *big.Int
	ks *keystore.KeyStore
	transactor *bind.TransactOpts
	key = []byte("super-secret-key")
	templates = template.Must(template.ParseFiles(
		"templates/main.html",
		"templates/login.html",
		"templates/account.html",
		"templates/history.html",
		"templates/transfer.html",
		"templates/nft.html",
		"templates/asset.html",
		"templates/tokens.html",
		"templates/token.html",
		"templates/footer.html",
	))
	store = sessions.NewCookieStore(key)
	validPath = regexp.MustCompile("^/(history|transfer|img|asset|token)/([a-z0-9]+)$")
)

func weiToEther(wei *big.Int) *big.Float {
	return new(big.Float).Quo(new(big.Float).SetInt(wei), big.NewFloat(params.Ether))
}

func etherToWei(eth *big.Float) *big.Int {
	truncInt, _ := eth.Int(nil)
	truncInt = new(big.Int).Mul(truncInt, big.NewInt(params.Ether))
	fracStr := strings.Split(fmt.Sprintf("%.18f", eth), ".")[1]
	fracStr += strings.Repeat("0", 18 - len(fracStr))
	fracInt, _ :=  new(big.Int).SetString(fracStr, 10)
	wei := new(big.Int).Add(truncInt, fracInt)

	return wei
}

func ParseBigFloat(value string) (*big.Float, error) {
	f := new(big.Float)
	f.SetPrec(236)  //  IEEE 754 octuple-precision binary floating-point format: binary256
	f.SetMode(big.ToNearestEven)
	_, err := fmt.Sscan(value, f)

	return f, err
}

func (t *Token) Symbol() string {
	if symbol, err := token.Symbol(&bind.CallOpts{}); err == nil {
		return symbol
	}
	log.Printf("token symbol err: %v", err)

	return "Not available now"
}

func (t *Token) Name() string {
	if name, err := token.Name(&bind.CallOpts{}); err == nil {
		return name
	}
	log.Printf("token name err: %v", err)

	return "Not available now"
}

func (t *Token) Account() *Account {
	if owner, err := token.OwnerOf(&bind.CallOpts{}, big.NewInt(t.Id)); err == nil {
		if acc, err := readAccount(owner.Hex()); err == nil {
			return acc
		}
		log.Printf("read acc err: %v", err)
	}
	log.Printf("ownerof err: %v", err)

	return nil
}

func (t *Token) Owner() string {
	if acc := t.Account(); acc != nil {
		return fmt.Sprintf("%s (%s)", acc.Id, acc.Email)
	}

	return "Not available now"
}

func (t *Token) URI() string {
	if uri, err := token.TokenURI(&bind.CallOpts{}, big.NewInt(t.Id)); err == nil {
		return uri
	}
	log.Printf("token uri err: %v", err)

	return "Not available now"
}

func (a *Account) Balance() *big.Float {
	account := common.HexToAddress(a.Id)
	balance, err := ethClient.BalanceAt(context.Background(), account, nil)
	ethBal := new(big.Float)
	if err == nil {
		ethBal.SetString(weiToEther(balance).String())
	} else {
		ethBal.SetString("0")
	}

	return ethBal
}

func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
	err = templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r, m[2])
	}
}

func login_page(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login", &Page{Title: "Login"})
}

func auth_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	// Authentication goes here
	if r.Method == "POST" {
		err = r.ParseForm()
		if err == nil {
			exists, err := participantExists(r.FormValue("email"))
			log.Printf("Participant %s exists: %v %v", r.FormValue("email"), exists, err)
			if err == nil {
				if !exists {
					participant, err := createParticipant(r.FormValue("email"), r.FormValue("password"))
					log.Printf("Create participant: %v", err)
					session.Values["authenticated"] = err == nil
					session.Values["email"] = participant.Email
					session.Values["participant_id"] = participant.Id
				} else {
					participant, err := readParticipant(r.FormValue("email"))
					log.Printf("Read participant: %v", err)
					if err == nil {
						session.Values["authenticated"] = participant.Passwd == xhashes.MD5(r.FormValue("password"))
						session.Values["email"] = participant.Email
						session.Values["participant_id"] = participant.Id
					}
				}
			}
		}
	}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func logout_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func main_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	participant_id, _ := session.Values["participant_id"].(int64)
	p := &Page{
		Title: email,
	}
	accounts, err := getParticipantAccounts(participant_id)
	if err == nil {
		for _, acc := range accounts {
			p.Chunks = append(p.Chunks, acc)
		}
	}
	session.Save(r, w)
	renderTemplate(w, "main", p)
}

func account_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	participant_id, _ := session.Values["participant_id"].(int64)
	switch r.Method {
	case "GET":
		p := &Page{
			Title: email,
		}
		session.Save(r, w)
		renderTemplate(w, "account", p)
	case "POST":
		if err = r.ParseForm(); err != nil {
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		var newAcc hexutil.Bytes
		err = rpcClient.Call(&newAcc, "personal_newAccount", r.FormValue("passwd"))
		log.Printf("Create personal account for %s: %v", email, err)
		if err == nil {
			_, err = createAccount(newAcc.String(), email, participant_id)
			log.Printf("Creating participant account for %s: %v", email, err)
			if err == nil {
				if amount, err := ParseBigFloat(r.FormValue("amount")); err == nil && amount.Cmp(big.NewFloat(0)) == 1 {
					var txHash hexutil.Bytes
					tx := Transaction{
						From:  *baseAccount,
						To:    newAcc.String(),
						Value: fmt.Sprintf("0x%x", etherToWei(amount)),
					}
					// @note: before run the application you should set the BASE_ACC_PASSWD environment variable
					err = rpcClient.Call(&txHash, "personal_sendTransaction", tx, os.Getenv("BASE_ACC_PASSWD"))
					log.Printf("Buy some coins %v: %v", txHash, err)
				} else {
					log.Printf("Convert amount %v err: %v", amount, err)
				}
			}
		}
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	}

}

func tokenHandler(w http.ResponseWriter, r *http.Request, id string) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	session.Save(r, w)

	t, err := readToken(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case "GET":
		p := &Page{
			Title: email,
			Token: t,
		}
		if accounts, err := getAllAccounts(); err == nil {
			for _, acc := range accounts {
				if acc.Id != t.Account().Id {
					p.Chunks = append(p.Chunks, acc)
				}
			}
		}
		renderTemplate(w, "token", p)
	case "POST":
		if err = r.ParseForm(); err == nil {
			ownerAcc := accounts.Account{
				Address: common.HexToAddress(t.Account().Id),
			}
			if err = ks.Unlock(ownerAcc, r.FormValue("password")); err == nil {
				if transferTransactor, err := bind.NewKeyStoreTransactorWithChainID(ks, ownerAcc, chainID); err == nil {
					if ttx, err := token.TransferFrom(
						transferTransactor,
						common.HexToAddress(t.Account().Id),
						common.HexToAddress(r.FormValue("new_owner")),
						big.NewInt(t.Id),
					); err == nil {
						log.Printf("transfer token tx hash: %v", ttx.Hash())
					}
					log.Printf("transfer token err: %v", err)
				}
				log.Printf("transfer transactor err: %v", err)
				err = ks.Lock(common.HexToAddress(t.Account().Id))
				log.Printf("Lock owner acc err: %v", err)
			}
			log.Printf("Transfer unlock err: %v", err)
		}
		log.Printf("Parse err: %v", err)
		http.Redirect(w, r, "/tokens", http.StatusFound)
	default:
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func assetHandler(w http.ResponseWriter, r *http.Request, id string) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)

	asset, err := readAsset(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	p := &Page{
		Title: email,
		Asset: asset,
	}
	session.Save(r, w)
	renderTemplate(w, "asset", p)
}

func imgHandler(w http.ResponseWriter, r *http.Request, id string) {
	asset, err := readAsset(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", asset.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(asset.Content)))
	imgLen, err := w.Write(asset.Content)
	log.Printf("img len: %v", imgLen)
	log.Printf("img err: %v", err)
}

func tokens_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	p := &Page{
		Title: email,
	}
	err := getAllTokens(&p.Chunks)
	log.Printf("getAllTokens err: %v", err)
	session.Save(r, w)
	renderTemplate(w, "tokens", p)
}

func nft_page(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	session.Save(r, w)

	switch r.Method {
	case "GET":
		p := &Page{
			Title: email,
		}
		if accounts, err := getAllAccounts(); err == nil {
			for _, acc := range accounts {
				p.Chunks = append(p.Chunks, acc)
			}
		}
		renderTemplate(w, "nft", p)
	case "POST":
		if err := r.ParseMultipartForm(10 << 20); err == nil {
			if file, handler, err := r.FormFile("image"); err == nil {
				defer file.Close()
				log.Printf("Uploaded File: %v", handler.Filename)
				log.Printf("File Size: %v", handler.Size)
				log.Printf("MIME Header: %v", handler.Header)

				if strings.HasPrefix(handler.Header["Content-Type"][0], "image") {
					if fileBytes, err := ioutil.ReadAll(file); err == nil {
						log.Printf("MD5: %s", xhashes.MD5(string(fileBytes)))
						if ntx, err := token.MintNFT(transactor, common.HexToAddress(r.FormValue("owner")), fmt.Sprintf(
							"/asset/%s",
							xhashes.MD5(string(fileBytes)),
						)); err == nil {
							log.Printf("Mint tx: %v", ntx.Hash())
							insertSQL := `insert into assets (id, name, description, content, content_type) values (?, ?, ?, ?, ?)`
							if stmt, err := sqliteDatabase.Prepare(insertSQL); err == nil {
								defer stmt.Close()
								result, err := stmt.Exec(
									xhashes.MD5(string(fileBytes)),
									r.FormValue("name"),
									r.FormValue("description"),
									fileBytes,
									handler.Header["Content-Type"][0],
								)
								log.Printf("Insert result: %v", result)
								log.Printf("Insert err: %v", err)
								// @note: now we will be waiting for transaction mined and emit Transfer event with new token_id
							}
							log.Printf("Prepare err: %v", err)
						}
						log.Printf("Mint err: %v", err)
					}
					log.Printf("Read file err: %v", err)
				}
			}
			log.Printf("File err: %v", err)
		}
		log.Printf("Parse err: %v", err)
		http.Redirect(w, r, "/tokens", http.StatusFound)
	default:
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func historyHandler(w http.ResponseWriter, r *http.Request, account string) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	acc, err := readAccount(account)
	if err != nil {
		session.Save(r, w)
		http.NotFound(w, r)
		return
	}
	p := &Page{
		Title: email,
		Account: acc,
	}
	err = getAccountHistory(acc, &p.Chunks)
	if err != nil {
		log.Printf("Error to get account history: %v", err)
	}
	session.Save(r, w)
	renderTemplate(w, "history", p)
}

func transferHandler(w http.ResponseWriter, r *http.Request, account string) {
	session, _ := store.Get(r, "cookie-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	email, _ := session.Values["email"].(string)
	sender, err := readAccount(account)
	if err != nil {
		session.Save(r, w)
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case "GET":
		p := &Page{
			Title: email,
			Account: sender,
		}
		accounts, err := getAllAccounts()
		if err == nil {
			for _, acc := range accounts {
				if acc.Id != account {
					p.Chunks = append(p.Chunks, acc)
				}
			}
		} else {
			log.Printf("Can not get all accounts: %v", err)
		}
		session.Save(r, w)
		renderTemplate(w, "transfer", p)
	case "POST":
		if err = r.ParseForm(); err != nil {
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if amount, err := ParseBigFloat(r.FormValue("amount")); err == nil && amount.Cmp(big.NewFloat(0)) == 1 {
			var txHash hexutil.Bytes
			tx := Transaction{
				From:  account,
				To:    r.FormValue("recipient"),
				Value: fmt.Sprintf("0x%x", etherToWei(amount)),
			}
			err = rpcClient.Call(&txHash, "personal_sendTransaction", tx, r.FormValue("password"))
			log.Printf("Transfer coins from %s to %s: %v, %v", account, r.FormValue("recipient"), txHash, err)
		}
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func getAccountHistory(acc *Account, result *[]interface{}) error {
	stmt, err := sqliteDatabase.Prepare("select * from ethtxs where lower(sender)=lower(?) or lower(recipient)=lower(?)")
	if err != nil {
		return fmt.Errorf("failed to get account %v history", acc.Id)
	}
	defer stmt.Close()

	rows, err := stmt.Query(acc.Id, acc.Id)
	if err != nil {
		return fmt.Errorf("failed to get account %v history", acc.Id)
	}
	defer rows.Close()

	for rows.Next() {
		var res HistoryResult
		var ts, gas, gasprice int64
		if err := rows.Scan(&ts, &res.Sender, &res.Recipient, &gas, &gasprice, &res.Block, &res.TxHash, &res.Value); err != nil {
			return fmt.Errorf("failed to get history result row: %v", err)
		}
		res.Time = time.Unix(ts, 0)
		res.Gas = weiToEther(big.NewInt(gas))
		res.GasPrice = weiToEther(big.NewInt(gasprice))
		*result = append(*result, res)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to iteration ober rows of %v account: %v", acc.Id, err)
	}

	return nil
}

func getAllTokens(tokens *[]interface {}) error {
	stmt, err := sqliteDatabase.Prepare("select distinct token_id from transfer_history")
	if err != nil {
		return fmt.Errorf("Failed to get tokens: %v", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return fmt.Errorf("Failed to get tokens: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.Id); err == nil {
			*tokens = append(*tokens, &t)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("Failed to iterating over rows of tokens: %v", err)
	}

	return nil
}

func getAllAccounts() ([]*Account, error) {
	stmt, err := sqliteDatabase.Prepare("select t1.id,t2.email from accounts as t1 left join participants as t2 on t2.id=t1.participant_id")
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %v", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query()
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %v", err)
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		var acc Account
		if err := rows.Scan(&acc.Id, &acc.Email); err != nil {
			return nil, fmt.Errorf("failed to get accounts: %v", err)
		}
		accounts = append(accounts, &acc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterating over rows of accounts: %v", err)
	}

	return accounts, nil
}

func getParticipantAccounts(participant_id int64) ([]*Account, error) {
	stmt, err := sqliteDatabase.Prepare("select t1.id, t2.email from accounts as t1 left join participants as t2 on t2.id=t1.participant_id  where t1.participant_id = ?")
	if err != nil {
		return nil, fmt.Errorf("failed to get participant %v accounts: %v", participant_id, err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(participant_id)
	if err != nil {
		return nil, fmt.Errorf("failed to get participant %v accounts: %v", participant_id, err)
	}
	defer rows.Close()

	var accounts []*Account
	for rows.Next() {
		var acc Account
		if err := rows.Scan(&acc.Id, &acc.Email); err != nil {
			return nil, fmt.Errorf("failed to get participant %v accounts: %v", participant_id, err)
		}
		accounts = append(accounts, &acc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterating over rows of participant %v accounts: %v", participant_id, err)
	}

	return accounts, nil
}

func participantExists(email string) (bool, error) {
	stmt, err := sqliteDatabase.Prepare("select count(*) from participants where email = ?")
	if err != nil {
		return false, fmt.Errorf("failed to get participant %s: %v", email, err)
	}
	defer stmt.Close()

	var cnt int
	err = stmt.QueryRow(email).Scan(&cnt)
	if err != nil {
		return false, fmt.Errorf("failed to get participant %s: %v", email, err)
	}

	return cnt > 0, nil
}

func createAccount(accId, email string, participantId int64) (*Account, error) {
	createSQL := `insert into accounts (id, participant_id) values (?, ?)`
	stmt, err := sqliteDatabase.Prepare(createSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create account %s: %v", accId, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(accId, participantId)
	if err != nil {
		return nil, fmt.Errorf("failed to create account %s: %v", accId, err)
	}

	var acc Account
	acc.Id = accId
	acc.Email = email

	return &acc, nil
}

func createParticipant(email, passwd string) (*Participant, error) {
	createSQL := `insert into participants (email, passwd) values (?, ?)`
	stmt, err := sqliteDatabase.Prepare(createSQL)
	if err != nil {
		return nil, fmt.Errorf("failed to create participant %s: %v", email, err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(email, xhashes.MD5(passwd))
	if err != nil {
		return nil, fmt.Errorf("failed to create participant %s: %v", email, err)
	}

	last_id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to create participant %s: %v", email, err)
	}

	var participant Participant
	participant.Id = last_id
	participant.Email = email
	participant.Passwd = xhashes.MD5(passwd)

	return &participant, nil
}

func readToken(id string) (*Token, error) {
	stmt, err := sqliteDatabase.Prepare("select token_id from transfer_history where token_id = ? limit 1")
	if err != nil {
		return nil, fmt.Errorf("failed to get token %s: %v", id, err)
	}
	defer stmt.Close()

	var t Token
	err = stmt.QueryRow(id).Scan(&t.Id)

	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("token %s does not exists", id)
	case err != nil:
		return nil, fmt.Errorf("failed to get token %s: %v", id, err)
	default:
		return &t, nil
	}
}

func readAsset(id string) (*Asset, error) {
	stmt, err := sqliteDatabase.Prepare("select * from assets where id = ?")
	if err != nil {
		return nil, fmt.Errorf("failed to get asset %s: %v", id, err)
	}
	defer stmt.Close()

	var asset Asset
	err = stmt.QueryRow(id).Scan(&asset.Id, &asset.Name, &asset.Description, &asset.Content, &asset.ContentType)

	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("asset %s does not exists", id)
	case err != nil:
		return nil, fmt.Errorf("failed to get asset %s: %v", id, err)
	default:
		return &asset, nil
	}
}

func readAccount(id string) (*Account, error) {
	stmt, err := sqliteDatabase.Prepare("select t1.id, t2.email from accounts as t1 left join participants as t2 on t2.id=t1.participant_id where lower(t1.id) = lower(?)")
	if err != nil {
		return nil, fmt.Errorf("failed to get account %s: %v", id, err)
	}
	defer stmt.Close()

	var account Account
	err = stmt.QueryRow(id).Scan(&account.Id, &account.Email)

	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("account %s does not exists", id)
	case err != nil:
		return nil, fmt.Errorf("failed to get account %s: %v", id, err)
	default:
		return &account, nil
	}
}

func readParticipant(email string) (*Participant, error) {
	stmt, err := sqliteDatabase.Prepare("select * from participants where email = ?")
	if err != nil {
		return nil, fmt.Errorf("failed to get participant %s: %v", email, err)
	}
	defer stmt.Close()

	var participant Participant
	err = stmt.QueryRow(email).Scan(&participant.Id, &participant.Email, &participant.Passwd)

	switch {
	case err == sql.ErrNoRows:
		return nil, fmt.Errorf("participant %s does not exists", email)
	case err != nil:
		return nil, fmt.Errorf("failed to get participan %s: %v", email, err)
	default:
		return &participant, nil
	}
}

func initDB() {
	initSQL := `create table participants (
		id integer not null primary key autoincrement,
		email varchar(255) not null unique,
		passwd varchar(255)
	);create table accounts (
		id varchar(255) not null primary key,
		participant_id integer not null,
		foreign key(participant_id) references participants(id)
	);create table ethtxs (
		time integer,
		sender text,
		recipient text,
		gas bigint,
		gasprice bigint,
		block integer,
		txhash text,
		value numeric
	);create table assets (
		id varchar(32) not null unique,
		name varchar(255) not null,
		description varchar(255) not null,
		content blob not null,
		content_type varchar(255) not null
	);create table transfer_history (
		ts timestamp not null default current_timestamp,
		sender varchar(255) not null,
		recipient varchar(255) not null,
		token_id integer not null
	);create index transfer_history_token_id_idx on transfer_history(token_id);`

	_, err := sqliteDatabase.Exec(initSQL)
	if err != nil {
		log.Fatalf("Can not init database: %v", err)
	}
}

func get_events() {
	contract := common.HexToAddress(*contractAddress)
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contract},
	}

	logs := make(chan types.Log)
	sub, err := ethClient.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatalf("Can not get subscriber: %v", err)
	}

	logTransferSig := []byte("Transfer(address,address,uint256)")
	logTransferSigHash := crypto.Keccak256Hash(logTransferSig)

	for {
		select {
		case err := <-sub.Err():
			log.Println(err)
		case vLog := <-logs:
			switch vLog.Topics[0].Hex() {
			case logTransferSigHash.Hex():
				log.Println("Log Name: Transfer")
				log.Printf("From: %s", common.HexToAddress(vLog.Topics[1].Hex()))
				log.Printf("To: %s", common.HexToAddress(vLog.Topics[2].Hex()))
				log.Printf("Token: %s", vLog.Topics[3].Big().String())
				log.Printf("Tx Hash: %s", vLog.TxHash.Hex())
				insertSQL := `insert into transfer_history (sender, recipient, token_id) values (?, ?, ?)`
				if stmt, err := sqliteDatabase.Prepare(insertSQL); err == nil {
					defer stmt.Close()
					result, err := stmt.Exec(
						common.HexToAddress(vLog.Topics[1].Hex()).Hex(),
						common.HexToAddress(vLog.Topics[2].Hex()).Hex(),
						vLog.Topics[3].Big().Int64(),
					)
					log.Printf("Insert result: %v", result)
					log.Printf("Insert err: %v", err)
				}
				log.Printf("Prepare insert err: %v", err)
			default:
				log.Println(vLog)
			}
		}
	}
}

func index_transactions() {
	// @note: infinite loop
	for {
		stmt, err := sqliteDatabase.Prepare("select max(block) from ethtxs")
		defer stmt.Close()

		startblock := big.NewInt(1).Uint64()
		if err == nil {
			_ = stmt.QueryRow().Scan(&startblock)
		}

		endblock, err := ethClient.BlockNumber(context.Background())
		if err != nil {
			endblock = big.NewInt(1).Uint64()
		}

		log.Printf("Current best block in index: %v; Current best block in index: %v", startblock, endblock)
		for i := startblock+1; i < endblock; i++ {
			block, err := ethClient.BlockByNumber(context.Background(), big.NewInt(int64(i)))
			if err == nil {
				for _, transaction := range block.Transactions() {
					message, err := transaction.AsMessage(types.LatestSignerForChainID(transaction.ChainId()), nil)
					if err == nil {
						log.Printf("mess val: %v, %T", message.Value(), message.Value())
						log.Printf("mess is_fake: %v", message.IsFake())
						log.Printf("mess data: %v", message.Data())
						log.Printf("From: %v", message.From().Hex())
						log.Printf("To: %v", message.To())
						to := message.To()
						var toHex string = ""
						if to != nil {
							toHex = to.Hex()
						}
						insertSQL := `insert into ethtxs (time, sender, recipient, gas, gasprice, block, txhash, value) values (?, ?, ?, ?, ?, ?, ?, ?)`
						insert, err := sqliteDatabase.Prepare(insertSQL)
						defer insert.Close()
						if err == nil {
							val, _ := weiToEther(message.Value()).Float64()
							_, err = insert.Exec(
								block.Time(),
								message.From().Hex(),
								toHex,
								message.Gas(),
								message.GasPrice().Uint64(),
								block.NumberU64(),
								transaction.Hash().Hex(),
								val,
							)
							if err != nil {
								log.Printf("Error insert record: %v", err)
							}
						}
					}
				}
			}
		}
		time.Sleep(20 * time.Second)
	}
}

func main() {
	// @note: set auto logoff to 5 minutes of idle
	store.MaxAge(300)
	dataDir = flag.String("data-dir", "~datadir", "Data dir")
	baseAccount = flag.String("base-account", "0x5883b8991821d1d80f9b64d44d2fc75cb8e2c16a", "Network base account")
	contractAddress = flag.String("contract-address", "0xeF17a56684F69d4d7Cea92852bDEd504EEd59463", "NFT contract address")
	httpHost := flag.String("http-host", "127.0.0.1", "Run http server on given host")
	httpPort := flag.Int("http-port", 6776, "Run http server on given port")

	flag.Parse()

	log.SetPrefix("ethereumapp: ")
	log.Println("=========== application starts ==========")

	ipc := fmt.Sprintf("%s/geth.ipc", *dataDir)
	ethClient, err = ethclient.Dial(ipc)
	if err != nil {
		log.Fatalf("Can not connect to ethereum network: %v", err)
	}
	defer ethClient.Close()

	chainID, err = ethClient.ChainID(context.Background())
	if err != nil {
		log.Fatalf("Can not get chain id: %v", err)
	}

	baseAcc := accounts.Account{
		Address: common.HexToAddress(*baseAccount),
	}
	ks = keystore.NewKeyStore(fmt.Sprintf("%s/keystore", *dataDir), keystore.StandardScryptN, keystore.StandardScryptP)
	err = ks.Unlock(baseAcc, os.Getenv("BASE_ACC_PASSWD"))
	if err != nil {
		log.Fatalf("Can not unlock base account")
	}

	transactor, err = bind.NewKeyStoreTransactorWithChainID(ks, baseAcc, chainID)
	if err != nil {
		log.Fatalf("Can not get transactor: %v", err)
	}

	token, err = nft.NewSampleNFT(common.HexToAddress(*contractAddress), ethClient)
	if err != nil {
		log.Fatalf("Can not get token: %v", err)
	}

	rpcClient, err = rpc.Dial(ipc)
	if err != nil {
		log.Fatalf("Can not get RPC client: %v", err)
	}
	defer rpcClient.Close()

	isCreated := false
	if _, err = os.Stat("sqlite-database.db"); os.IsNotExist(err) {
		file, err := os.Create("sqlite-database.db")
		if err != nil {
			log.Fatalf("Can not create database: %v", err)
		}
		file.Close()
		log.Println("sqlite-database.db created")
		isCreated = true
	}

	sqliteDatabase, err = sql.Open("sqlite3", "file:sqlite-database.db?_foreign_keys=on")
	if err != nil {
		log.Fatalf("Can not open sqlite3 database: %v", err)
	}
	defer sqliteDatabase.Close()

	if isCreated {
		initDB()
	}

	go index_transactions()
	go get_events()

	http.HandleFunc("/", main_page)
	http.HandleFunc("/login", login_page)
	http.HandleFunc("/logout", logout_page)
	http.HandleFunc("/account", account_page)
	http.HandleFunc("/nft", nft_page)
	http.HandleFunc("/tokens", tokens_page)
	http.HandleFunc("/auth", auth_page)
	http.HandleFunc("/history/", makeHandler(historyHandler))
	http.HandleFunc("/transfer/", makeHandler(transferHandler))
	http.HandleFunc("/img/", makeHandler(imgHandler))
	http.HandleFunc("/asset/", makeHandler(assetHandler))
	http.HandleFunc("/token/", makeHandler(tokenHandler))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *httpHost, *httpPort), nil))
}
