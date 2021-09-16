package main

import (
    "bytes"
    "context"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "math/rand"
    "net/http"
    "sync"
    "sync/atomic"
    "time"

    "github.com/gorilla/websocket"
    "github.com/spf13/cobra"

    "castor.kryptus/agamotto/audit-server/sas/utils"
    "castor.kryptus/agamotto/commons/audit"
    "castor.kryptus/agamotto/commons/common"
    "castor.kryptus/agamotto/commons/logger"
    "castor.kryptus/agamotto/commons/management_interface"
    "castor.kryptus/agamotto/commons/setup"
)

type ConnChannel struct {
    readChannel                 *chan []byte
    TimestampCertificateRawSubj []byte
    time                        string
    timer                       *time.Timer
    SSLCertificate              []byte
    TCT                         *audit.TimeChainingTree
}

type TSS struct {
    Id                           int                 `json:"id"`
    AuthorizedSSLCertificate     string              `json:"authorized_ssl_certificate"`
    TimestampCertificate         string              `json:"timestamp_certificate"`
    IsTimeSynchronizationEnabled bool                `json:"is_time_synchronization_enabled"`
    IsTimeAuditEnabled           bool                `json:"is_time_audit_enabled"`
    AuthorizedIP                 string              `json:"authorized_ip"`
    TimestampAuthority           int                 `json:"timestamp_authority"`
    TCRParameters                utils.TCRParameters `json:"tcr_parameters"`
}

var serverStartTime time.Time

var ForceAuditWaitDuration time.Duration

var upgrader = websocket.Upgrader{} // use default options

var connectionsMap = map[string]*ConnChannel{}

var numActiveConnections common.Counter

var cmdServer = &cobra.Command{
    Use:   "server",
    Short: "Starts an HTTPS server",
    Long:  "Starts an HTTPS server that responds to audit requests.",
    PreRun: func(cmd *cobra.Command, args []string) {
        // Binding flags with viper
        setup.Flags.BindPFlag("develMode", cmd.Flags().Lookup("develMode"))
        setup.Flags.BindPFlag("testCli", cmd.Flags().Lookup("testCli"))
    },
    Run: runServer,
}

var callRequestAudit uint64
var callRequestAuditSucceeded uint64
var callRequestAuditFailed uint64
var tcrFileGeneratedError uint64

func init() {
    numActiveConnections.Zero()
    // Parse flags
    cmdServer.Flags().BoolP("develMode", "d", false, "Bypass some checks to allow easier development")

    rootCmd.AddCommand(cmdServer)
}

func runServer(cmd *cobra.Command, args []string) {
    serverStartTime = time.Now()
    rand.Seed(time.Now().UTC().UnixNano())

    // Create a channel to restart the config, if requested
    setup.RestartServerSig = make(chan bool)

    err := setup.LoadConfig()
    if err != nil {
        logger.LogGeneralFatal("Could not load objects", err)
    }

    var httpsServer *http.Server
    serverChan := make(chan *http.Server)

    ForceAuditWaitDuration = time.Second * time.Duration(setup.Config.GetInt("forceAuditWaitDuration"))

    go startServer(serverChan)
    go startEventsServer()

    httpsServer = <-serverChan

    for {
        select {
        case <-setup.RestartServerSig:

            logger.LogGeneralInfo("Closing HTTPS server")

            err := httpsServer.Shutdown(context.Background())
            if err != nil {
                logger.LogGeneralError("Error closing the HTTPS auditor server", err)
            } else {
                logger.LogGeneralInfo("Successfully closed the HTTPS auditor server")
            }

            logger.LogGeneralInfo("Restarting HTTPS auditor server")
            go startServer(serverChan)
            httpsServer = <-serverChan
        }
    }
}

func startEventsServer() {
    mux := http.NewServeMux()
    mux.HandleFunc(setup.Config.GetString("events.uri"), eventControl)

    httpsServer := &http.Server{
        Addr:    fmt.Sprintf("%s:%d", setup.Config.GetString("events.ip"), setup.Config.GetInt("events.port")),
        Handler: mux,
    }
    err := httpsServer.ListenAndServe()
    if err != nil && err != http.ErrServerClosed {
        logger.LogGeneralFatal("Events HTTPS server error", err)
    }
}

func eventControl(w http.ResponseWriter, r *http.Request) {

    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        logger.LogGeneralWarning("eventControl message could not be read", err)
        return
    }

    message, err := common.DecodeMessage(body)
    if err != nil {
        logger.LogGeneralWarning("eventControl message could not be decoded", err)
        return
    }

    switch message.Operation {
    case common.ForceAuditEvent:
        w.Write(body)
        forceAudit(message.Content)
    case common.GetSNMPDataOperation:
        pay := executeGetSNMPDataOperation()
        payJSON, err := json.Marshal(pay)
        if err != nil {
            logger.LogGeneralError("Couldn't marshal SNMP response", err)
            return
        }
        w.Write(payJSON)
    case common.GetAuditStatistics:
        pay := executeAuditStatistics()
        payJSON, err := json.Marshal(pay)
        if err != nil {
            logger.LogGeneralError("Couldn't marshal Audit Statistics response", err)
            return
        }
        w.Write(payJSON)
    case common.GetKnetCredentials:
        err := setup.SetupKNETConnection()
        if err != nil {
            logger.LogGeneralError("update knet credentials: Bad response from UI", err)
        }
    default:
        logger.LogGeneralError("unknown event type", nil)
    }
}

func forceAudit(content interface{}) {
    connectionID, ok := content.(string)
    if !ok {
        logger.LogGeneralError("forceAudit Contant must be string", nil)
        return
    }

    _, ok = connectionsMap[connectionID]
    if !ok {
        logger.LogGeneralWarning("forceAudit was called for a connectionID that doesn't exist ("+connectionID+")", nil)
        return
    }

    messageToSend, err := common.EncodeForceAuditRequest()
    if err != nil {
        return
    }
    //Write to the readChannel that is associated with connectionID
    // so we can forward the message in its messageControl thread
    *(connectionsMap[connectionID].readChannel) <- messageToSend
}

func getTSSFromSSLCert(cert []byte) (TSS, error) {
    var tsses []TSS

    resp, err := http.Get(setup.Config.GetString("sas.availableTSSesEndpoint"))
    if err != nil {
        return TSS{}, err
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return TSS{}, err
    }
    sb := string(body)
    // Unmarshal request response
    json.Unmarshal([]byte(sb), &tsses)

    for _, tss := range tsses {
        block, _ := pem.Decode([]byte(tss.AuthorizedSSLCertificate))
        if block == nil {
            return TSS{}, errors.New("Could not Decode Certificate")
        }
        if bytes.Equal(block.Bytes, cert) {
            return tss, nil
        }
    }
    return TSS{}, errors.New("Certificate not registered in Audit Server")
}

func parseTimestampCert(cert string) (*x509.Certificate, error) {
    if cert == "" {
        return nil, errors.New("no timestamp certificate registered")
    }

    block, _ := pem.Decode([]byte(cert))
    if block == nil {
        return nil, errors.New("no PEM timestamp certificate present")
    }
    return x509.ParseCertificate(block.Bytes)
}

func verifyCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
    _, err := getTSSFromSSLCert(rawCerts[0])
    return err
}

func startServer(serverChan chan<- *http.Server) {
    // Setup function that will handle requests sent to the configured URI
    mux := http.NewServeMux()
    mux.HandleFunc(setup.Config.GetString("server.uri"), auditor)

    tlsConfig := &tls.Config{
        GetCertificate: setup.GetTLSServerCertificate,
        MinVersion:     tls.VersionTLS12,
        ClientAuth:     tls.RequireAnyClientCert,
        //verifyCertification using getTSSFromSSLCert is done in auditor
    }

    httpsServer := &http.Server{
        Addr:      fmt.Sprintf("%s:%d", setup.Config.GetString("server.ip"), setup.Config.GetInt("server.port")),
        Handler:   mux,
        TLSConfig: tlsConfig,
    }

    // Send the newly created server to the mainloop
    serverChan <- httpsServer

    err := httpsServer.ListenAndServeTLS("", "")
    if err != nil && err != http.ErrServerClosed {
        logger.LogGeneralFatal("Auditor HTTPS server error", err)
    }
}

func auditor(w http.ResponseWriter, r *http.Request) {
    tss, err := getTSSFromSSLCert(r.TLS.PeerCertificates[0].Raw)
    if err != nil {
        logger.LogAuditError("Mutal authentication: Error getting TSS from registered SSL certificates", r.Host, r.RemoteAddr, "", err)
        return
    }

    hashCert := sha256.Sum256([]byte(tss.AuthorizedSSLCertificate))
    connectionID := base64.StdEncoding.EncodeToString(hashCert[:])
    logger.LogAudit("Mutal authentication: TSS successfuly authenticated with registered SSL certificates", r.Host, r.RemoteAddr, connectionID)

    timestampCert, err := parseTimestampCert(tss.TimestampCertificate)
    if err != nil {
        logger.LogAuditError("Error parsing peer timestamp certificate", r.Host, r.RemoteAddr, connectionID, err)
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        logger.LogAuditError("Websocket upgrade error", r.Host, r.RemoteAddr, connectionID, err)
        return
    }

    if _, ok := connectionsMap[connectionID]; ok {
        logger.LogAuditError("Client with the same certificate already exists. Sending error message to client", r.Host, r.RemoteAddr, connectionID, nil)
        messageToSend, err := common.EncodeErrorMessage("Client with the same certificate already connected")
        if err != nil {
            logger.LogAuditError("Could not mount EncodeErrorMessage", r.Host, r.RemoteAddr, connectionID, err)
        }
        conn.WriteMessage(websocket.BinaryMessage, messageToSend)
        return
    }

    waitGroup := &sync.WaitGroup{}
    waitGroup.Add(3)

    writeChannel := make(chan []byte)
    readChannel := make(chan []byte)
    errorChannel := make(chan struct{})

    go readMessage(conn, readChannel, errorChannel, waitGroup)
    go writeMessage(conn, writeChannel, errorChannel, waitGroup)
    go messageControl(conn, writeChannel, readChannel, errorChannel, waitGroup, connectionID)

    decodedSSLCert, _ := pem.Decode([]byte(tss.AuthorizedSSLCertificate))

    var tsCertSubj []byte

    if timestampCert != nil {
        tsCertSubj = timestampCert.RawSubject
    }

    connectionsMap[connectionID] = &ConnChannel{
        readChannel:                 &readChannel,
        TimestampCertificateRawSubj: tsCertSubj,
        time:                        "",
        timer:                       nil,
        SSLCertificate:              decodedSSLCert.Bytes,
        TCT:                         nil,
    }

    numActiveConnections.Increment()
    logger.LogAudit("Succesfully created new auditor handler", r.Host, r.RemoteAddr, connectionID)
}

func closeConnection(conn *websocket.Conn) {
    err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
    if err != nil {
        logger.LogGeneralError("Error while closing the websocket", err)
        return
    }
    logger.LogGeneralInfo(fmt.Sprintf("Closed websocket connection with: %s", conn.UnderlyingConn().RemoteAddr().String()))
}

func messageControl(conn *websocket.Conn, writeChannel chan []byte, readChannel chan []byte, errorChannel chan struct{}, waitGroup *sync.WaitGroup, connectionID string) {
    localAddr := conn.LocalAddr().String()
    remoteAddr := conn.RemoteAddr().String()

L:
    for {
        select {
        case encodedMessage := <-readChannel:

            message, err := common.DecodeMessage(encodedMessage)
            if err != nil {
                break
            }

            switch message.Operation {
            // Audit procedure ////////////////////////////////////////////////
            // First message in the audit procedure
            case common.AuditRequest:
                tss, err := getTSSFromSSLCert((connectionsMap[connectionID].SSLCertificate))
                if err != nil || !tss.IsTimeAuditEnabled {
                    break
                }
                connectionsMap[connectionID].time = time.Now().UTC().String()

                atomic.AddUint64(&callRequestAudit, 1)
                // fmt.Printf("Audit Request: %d time(s)\n", callRequestAudit)
                // Request the current TCT
                messageToSend, err := common.EncodeMerkleAuditTCTRequestMessage()
                if err != nil {
                    atomic.AddUint64(&callRequestAuditFailed, 1)
                    // fmt.Printf("Audit Request Failed: %d time(s)\n", callRequestAuditFailed)
                    break
                }
                writeChannel <- messageToSend
                atomic.AddUint64(&callRequestAuditSucceeded, 1)
                // fmt.Printf("Audit Request Succeeded: %d time(s)\n", callRequestAuditSucceeded)
                // TODO: timeout if the SCT don't respond?

            // Receive the Time Chaining Tree block
            case common.MerkleAuditResponseTCT:
                if message.Content == nil {
                    logger.LogGeneralAuditError("Nil Time Chaining Tree received, aborting audit...", localAddr, remoteAddr, nil)
                    break
                }

                // go's json encoder encodes binary data to base64, so
                // we need to decode a base64 after receiving it
                b64TCT := message.Content.(string)
                rawTCT, err := base64.StdEncoding.DecodeString(b64TCT)
                if err != nil {
                    logger.LogGeneralAuditError("Error decoding the received Time Chaining Tree, aborting audit...", localAddr, remoteAddr, err)
                    break
                }

                // Parse the TCT bytes into the struct
                connectionsMap[connectionID].TCT, err = audit.UnmarshalTimeChainingTree(rawTCT)
                if err != nil {
                    logger.LogGeneralAuditError("Error parsing the received Time Chaining Tree, aborting audit...", localAddr, remoteAddr, err)
                    break
                } else {
                    logger.LogTimeChainingTreeReceived(
                        connectionsMap[connectionID].TCT.SequenceNumber,
                        connectionsMap[connectionID].TCT.LeafCount,
                        connectionsMap[connectionID].TCT.BitSize,
                        connectionsMap[connectionID].TCT.TimestampEnd,
                        connectionsMap[connectionID].TCT.Root,
                        connectionsMap[connectionID].TCT.PrevHash,
                        connectionsMap[connectionID].TCT.Hash,
                    )
                }

                // request the current TCR
                messageToSend, err := common.EncodeMerkleAuditTCRRequestMessage()
                if err != nil {
                    logger.LogGeneralAuditError("Error requesting the current TCR, aborting audit...", localAddr, remoteAddr, err)
                    sctCertificate := connectionsMap[connectionID].SSLCertificate
                    sctCertificateStr := base64.StdEncoding.EncodeToString(sctCertificate)

                    email_err := management_interface.EmailASAuditError(err, sctCertificateStr)
                    if email_err != nil {
                        logger.LogGeneralError("Error to send e-mail", email_err)
                    }
                    break
                }
                writeChannel <- messageToSend

            // Receive the current TCR to check if the previous TCT hash is the same as the one in the TCR
            case common.MerkleAuditResponseTCR:
                if !setup.Flags.GetBool("develMode") {
                    // The only exception we have here is if this is the first audit ever for this SCT
                    if message.Content == nil && connectionsMap[connectionID].TCT.SequenceNumber != 0 {
                        logger.LogGeneralAuditError("Nil TCR received, aborting audit...", localAddr, remoteAddr, nil)
                        break
                    }

                    if message.Content != nil {
                        // we need to decode a base64 after receiving it
                        b64TCR := message.Content.(string)
                        rawTCR, err := base64.StdEncoding.DecodeString(b64TCR)
                        if err != nil {
                            logger.LogGeneralAuditError("Error decoding the received Time Chaining Tree, aborting audit...", localAddr, remoteAddr, err)
                            break
                        }

                        previousTCTHash, err := getTCTHashFromRawTCR(rawTCR)
                        if err != nil {
                            logger.LogGeneralAuditError("Error retrieving the last Time Chaining Tree hash from the TCR, aborting audit...", localAddr, remoteAddr, err)
                            break
                        }

                        // TODO: Verify signature here
                        isValid, err := utils.VerifyTCRInfo(rawTCR, setup.GetSignerCertificate())
                        if err != nil {
                            logger.LogGeneralAuditError("Failed to verify the TCR signature, aborting audit...", localAddr, remoteAddr, err)
                            break
                        } else if !isValid {
                            logger.LogGeneralAuditError("TCR signature invalid, aborting audit...", localAddr, remoteAddr, err)
                            break
                        }

                        if !bytes.Equal(previousTCTHash, connectionsMap[connectionID].TCT.PrevHash) {
                            logger.LogGeneralAuditError("Previous Time Chaining Tree hash differs from the one present on the TCR, aborting audit...", localAddr, remoteAddr, err)
                            break
                        }
                    }
                }

                // request the log (leafs)
                messageToSend, err := common.EncodeMerkleAuditLeafsRequestMessage()
                if err != nil {
                    logger.LogGeneralAuditError("Error requesting the Merkle leaves, aborting audit...", localAddr, remoteAddr, err)
                    sctCertificate := connectionsMap[connectionID].SSLCertificate
                    sctCertificateStr := base64.StdEncoding.EncodeToString(sctCertificate)

                    email_err := management_interface.EmailASAuditError(err, sctCertificateStr)
                    if email_err != nil {
                        logger.LogGeneralError("Error to send e-mail", email_err)
                    }
                    break
                }
                writeChannel <- messageToSend

            // The auditing happens here
            case common.MerkleAuditResponseLeafs:
                if message.Content == nil {
                    logger.LogGeneralAuditError("No Time Chaining Tree Merkle leafs received, aborting audit...", localAddr, remoteAddr, nil)
                    connectionsMap[connectionID].TCT = nil
                    break
                }
                tss, err := getTSSFromSSLCert((connectionsMap[connectionID].SSLCertificate))
                if err != nil || !tss.IsTimeAuditEnabled {
                    break
                }
                // Check if the signer certificate has not yet expired
                if time.Now().After(setup.GetSignerCertificate().NotAfter) {
                    // TODO: Should we alert the SCT if the SAS certificate has expired?
                    logger.LogCertificateExpired("Time Calibration Report", setup.GetSignerCertificate().NotAfter, time.Now())
                    break
                }

                tss, _ = getTSSFromSSLCert((connectionsMap[connectionID].SSLCertificate))
                isValid, reason, delay, offset, err := MerkleAudit(*connectionsMap[connectionID].TCT, tss.TCRParameters, message.Content, localAddr, remoteAddr)
                if err != nil {
                    logger.LogGeneralAuditError("Error during the audit process", localAddr, remoteAddr, err)
                } else {
                    logger.LogGeneralAuditInfo("Audit finished successfully", localAddr, remoteAddr)
                }

                
