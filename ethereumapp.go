//go:generate abigen --sol nft.sol --pkg main --out nft.go

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
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/sessions"
	"github.com/shomali11/util/xhashes"
	_ "github.com/mattn/go-sqlite3"
)

type Page struct {
	Title   string
	Account *Account
	Chunks  []interface{}
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
	baseAccount *string
	sqliteDatabase *sql.DB
	rpcClient *rpc.Client
	ethClient *ethclient.Client
	key = []byte("super-secret-key")
	templates = template.Must(template.ParseFiles("main.html", "login.html", "account.html", "history.html", "transfer.html"))
	store = sessions.NewCookieStore(key)
	validPath = regexp.MustCompile("^/(history|transfer)/([a-z0-9]+)$")
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
		if err := r.ParseForm(); err != nil {
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
		if err := r.ParseForm(); err != nil {
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

func readAccount(id string) (*Account, error) {
	stmt, err := sqliteDatabase.Prepare("select t1.id, t2.email from accounts as t1 left join participants as t2 on t2.id=t1.participant_id where t1.id = ?")
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
	);`

	_, err := sqliteDatabase.Exec(initSQL)
	if err != nil {
		log.Fatalf("Can not init database: %v", err)
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
	dataDir := flag.String("data-dir", "~datadir", "Data dir")
	baseAccount = flag.String("base-account", "0x5883b8991821d1d80f9b64d44d2fc75cb8e2c16a", "Network base account")
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

	http.HandleFunc("/", main_page)
	http.HandleFunc("/login", login_page)
	http.HandleFunc("/logout", logout_page)
	http.HandleFunc("/account", account_page)
	http.HandleFunc("/auth", auth_page)
	http.HandleFunc("/history/", makeHandler(historyHandler))
	http.HandleFunc("/transfer/", makeHandler(transferHandler))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *httpHost, *httpPort), nil))
}
