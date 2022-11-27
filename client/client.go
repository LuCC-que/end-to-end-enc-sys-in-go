package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"bytes"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string							`json:"Username"`
	UserID userlib.UUID					`json:"UserID"`
	KeyHubs map[string][]byte 	`json:"KeyHubs"`
	FileRevoke map[string]int		`json:"FileRevoke"`
	PrivateKey []byte						`json:"PrivateKey"`
	UserMac []byte							`json:"UserMac"`

	//don't save in dataStore
	InterimData InterimData

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type InterimData struct{
	MasterKey []byte
}

type File struct{
	FileId userlib.UUID
	Signatures []byte
	Content []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func formate_checker(username string, password string) (ok bool){

	if(username == "" || len(username) == 0 || 
			password == "" || len(password) == 0){
		return false
	}

	return true

}

func properly_save_userData(master_key []byte, username_hash []byte, saveble User) (err error){

	//remove the interimData, give a empty one to it
	saveble.InterimData = InterimData{}

	json_userdata, err := json.Marshal(saveble)
	if err != nil{
		return errors.New(strings.ToTitle("Internel error: Fail to generate Mashal for json_userdata"))
	}

	// encrypt the data store
	purpose2 := append(username_hash, "/encryptDataStroage"...)
	enc_data_Store_key, err := userlib.HashKDF(master_key[:16], purpose2)
	if err != nil{
		return errors.New(strings.ToTitle("Internel error[HashKDF]: Fail to generate enc_data_Store_key"))
	}

	
	IV := userlib.RandomBytes(16)
	cipherUserdata := userlib.SymEnc(enc_data_Store_key[:16], IV, json_userdata)

	//save to the data store
	userlib.DatastoreSet(saveble.UserID, cipherUserdata)

	return nil

}
func InitUser(username string, password string) (userdataptr *User, err error) {
	
	//formate checking
	format := formate_checker(username, password)
	if !format {
		return nil, errors.New(strings.ToTitle("username or password can't be empty"))
	}

	//generate name hash and uuid
	username_hash := userlib.Hash([]byte(username))
	user_uuid, err:= uuid.FromBytes(username_hash[:16])
	if err!= nil{
		return nil, errors.New(strings.ToTitle("Internel error: Fail to create uuid"))
	}

	// make sure there is no same user name
	_, ok := userlib.DatastoreGet(user_uuid)

	if ok{
		return nil, errors.New(strings.ToTitle("username exist, choose another one"))
	}

	//create a password has and drive a key from it
	password_hash := userlib.Hash([]byte(password))
	master_key := userlib.Argon2Key(password_hash, username_hash, 64)

	//combine username hash and password hash gen a user MAC code
	combine_name_password := append(username_hash, password_hash...)
	user_mac, err:= userlib.HMACEval(master_key[:16], combine_name_password)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[init]: Fail to create user MAC"))
	}
	
	// create pub and pri key
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil{
		return nil, errors.New(strings.ToTitle("Internel error: Fail to generate PKEkeys"))
	}

	//publish the personal public key
	userlib.KeystoreSet(username, PKEEncKey)
	
	// gen a key from master key for privateKey
	purpose := append(username_hash, "/privateKey"...)
	pri_enc_key, err := userlib.HashKDF(master_key[:16], purpose)
	if err != nil{
		return nil, errors.New(strings.ToTitle("Internel error[HashKDF, init]: Fail to generate pri_enc_key"))
	}

	//turn the prikey into Json
	json_pri_enc_key, err := json.Marshal(PKEDecKey)
	if err != nil{
		return nil, errors.New(strings.ToTitle("Internel error: Fail to generate Mashal for json_pri_enc_key"))
	}

	//encrypt it and save it to the userdata struct
	IV := userlib.RandomBytes(16)
	cipherPriKey := userlib.SymEnc(pri_enc_key[:16], IV, json_pri_enc_key)

	InterimData := InterimData{
		master_key,
	}

	userdata := User{
		Username: username,
		UserID: user_uuid,
		KeyHubs: make(map[string][]byte),
		FileRevoke: make(map[string]int),
		PrivateKey: cipherPriKey,
		UserMac: user_mac,
		InterimData: InterimData,
	}


	err = properly_save_userData(master_key, username_hash, userdata)
	if err != nil{
		return nil, errors.New(strings.ToTitle("Fail to save the data in to th data store"))
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
		
	//formate checking
	format := formate_checker(username, password)
	if !format {
		return nil, errors.New(strings.ToTitle("username or password can't be empty"))
	}

	//generate name hash and uuid
	username_hash := userlib.Hash([]byte(username))
	user_uuid, err:= uuid.FromBytes(username_hash[:16])
	if err!= nil{
		return nil, errors.New(strings.ToTitle("Internel error: Fail to create uuid"))
	}

	// make sure there is no same user name
	dataJSONCipher, ok := userlib.DatastoreGet(user_uuid)

	if !ok{
		return nil, errors.New(strings.ToTitle("User doesn't exist"))
	}

	//create a password has and drive a key from it
	password_hash := userlib.Hash([]byte(password))
	master_key := userlib.Argon2Key(password_hash, username_hash, 64)

	// decrypt the data store and make a proper data stor
	purpose2 := append(username_hash, "/encryptDataStroage"...)
	data_Store_key, err := userlib.HashKDF(master_key[:16], purpose2)
	if err != nil{
		return nil, errors.New(strings.ToTitle("Internel error[HashKDF]: Fail to generate data_Store_key"))
	}
	dataJSONPlain := userlib.SymDec(data_Store_key[:16], dataJSONCipher)
	var userdata User
	err = json.Unmarshal(dataJSONPlain, &userdata)
	if err != nil{
		return nil, errors.New(strings.ToTitle("Internel error: Saved data compromised or password incorrect"))
	}

	//combine username hash and password hash gen a user MAC code
	//and the compare the MACs
	combine_name_password := append(username_hash, password_hash...)
	valid_user_Mac, err :=  userlib.HMACEval(master_key[:16], combine_name_password)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to create user MAC"))
	}
	res := bytes.Compare(valid_user_Mac, userdata.UserMac)
	if res != 0{
		return nil, errors.New(strings.ToTitle("Password or username incorrect"))

	}

	//make interim data
	interimData := InterimData{
		master_key,
	}	
	
	//attach to the userdata
	userdata.InterimData = interimData

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	userDataChange := false
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(storageKey)
	username_hash := userlib.Hash([]byte(userdata.Username))
	filename_hash := userlib.Hash([]byte(filename))
	var cipherContent []byte

	var DSSignKey userlib.DSSignKey
	var DSVerifyKey userlib.DSVerifyKey
	IV := userlib.RandomBytes(16)

	// encrypt the data
	contentBytes, err := json.Marshal(content)
	if ok{
		revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
		description := append([]byte("/contentEncryption/"), revokeCounter...)
		// userlib.DebugMsg("This is the description, of OK", string(description))
		contentKeyPurpose := append(append(username_hash, filename_hash...),  description...)
		// userlib.DebugMsg("This is the contentKeyPurpose, of OK", string(contentKeyPurpose))
		contentKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(1)"))
		}
		cipherContent = userlib.SymEnc(contentKey[:16], IV, contentBytes)
		// userlib.DebugMsg("This is the content key, of OK", string(contentKey))
		// get the DSvKey
		publishName := append(append(username_hash, "/"...), filename_hash...)
		DSVerifyKey, ok:= userlib.KeystoreGet(string(publishName))
		if !ok {
			return errors.New(strings.Title("Can't find the key"))
		}

		// get the DSsKey
		json_pub_key, err := json.Marshal(DSVerifyKey)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pub key)"))
		}

		//decrpt the pri_key
		cipher_json_pri_key := userdata.KeyHubs[string(json_pub_key)]
		priKeyPurpose := append(append(username_hash, filename_hash...),  "/privateKeyEnc"...)
		key_of_priKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], priKeyPurpose)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to HashKDP pri key(1)"))
		}

		json_pri_key := userlib.SymDec(key_of_priKey[:16], cipher_json_pri_key)

		// unmarshal the DSskey
		err = json.Unmarshal(json_pri_key, &DSSignKey)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to unmarsh priv key)"))
		}

	}else{
		description := append([]byte("/contentEncryption/revokeCounter"), byte(0))
		// userlib.DebugMsg("This is the description, of not OK", string(description))
		contentKeyPurpose := append(append(username_hash, filename_hash...), description...)
		// userlib.DebugMsg("This is the contentKeyPurpose, of not OK", string(contentKeyPurpose))
		contentKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(2)"))
		}
		//userlib.DebugMsg("This is the content key, of not OK", string(contentKey))
		cipherContent = userlib.SymEnc(contentKey[:16], IV, contentBytes)
		userdata.FileRevoke[string(filename_hash)] = 0
		
		DSSignKey, DSVerifyKey, err = userlib.DSKeyGen()
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen Signatures(1)"))
		}

		// publish the new pub key
		publishName := append(append(username_hash, "/"...), filename_hash...)
		userlib.KeystoreSet(string(publishName), DSVerifyKey)
		//add to the user data
		json_pub_key, err := json.Marshal(DSVerifyKey)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pub key)"))
		}
		json_pri_key, err := json.Marshal(DSSignKey)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pri key)"))
		}

		//encrypt the private key
		priKeyPurpose := append(append(username_hash, filename_hash...),  "/privateKeyEnc"...)
		key_of_priKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], priKeyPurpose)
		if err != nil{
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to HashKDP pri key)"))
		}

		IV = userlib.RandomBytes(16)
		cipher_pri_key := userlib.SymEnc(key_of_priKey[:16], IV, json_pri_key)

		userdata.KeyHubs[string(json_pub_key)] = cipher_pri_key
		userDataChange = true
	}

	//make a Signatures
	Signatures, err := userlib.DSSign(DSSignKey, cipherContent)
	if err != nil{
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen Signatures(2)"))
	}

	//make the file data	
	fileData := File{
		FileId: storageKey,
		Signatures: Signatures,
		Content: cipherContent,
	}

	//make the cipher file data and save it
	json_fileData, err := json.Marshal(fileData)
	if err != nil{
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen Marshal"))
	}
	revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
	description := append([]byte("/dataEncryption/"), revokeCounter...)
	dataKeyPurpose := append(append(username_hash, filename_hash...),  description...)
	IV = userlib.RandomBytes(16)
	dataKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
	if err != nil{
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(3)"))
	}
	cipherFileData := userlib.SymEnc(dataKey[:16], IV, json_fileData)
	userlib.DatastoreSet(storageKey, cipherFileData)

	

	// save the data
	if userDataChange{
		properly_save_userData(userdata.InterimData.MasterKey, username_hash, *userdata)
	}
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}

	username_hash := userlib.Hash([]byte(userdata.Username))
	filename_hash := userlib.Hash([]byte(filename))

	//make two keys, contingenally
	var dataKey []byte
	var contentKey []byte
	var cipher_json_fileData []byte
	var fileData File
	cipher_json_fileData, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New(strings.ToTitle("[AppendToFile]: file doesn't exist"))
	}else{
		revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
		data_description := append([]byte("/dataEncryption/"), revokeCounter...)
		dataKeyPurpose := append(append(username_hash, filename_hash...),  data_description...)
		dataKey, err= userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
		if err != nil{
			return errors.New(strings.ToTitle("[AppendToFile]: fail to HashKDF(1)"))
		}
		
		content_description := append([]byte("/contentEncryption/"), revokeCounter...)
		contentKeyPurpose := append(append(username_hash, filename_hash...),  content_description...)
		contentKey, err= userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
		userlib.DebugMsg("This is the content key, of not append store", string(contentKey))
		if err != nil{
			return errors.New(strings.ToTitle("[AppendToFile]: fail to HashKDF(2)"))
		}

	}
	
	//check if is the owner or not then do the enc or dec
	// make a key to decrpt the data
	json_fileData := userlib.SymDec(dataKey[:16], cipher_json_fileData)
	err = json.Unmarshal(json_fileData, &fileData)
	if err != nil{
		return errors.New(strings.ToTitle("[AppendToFile]: fail to unmarshal"))
	}

	//check signature
	publishName := append(append(username_hash, "/"...), filename_hash...)
	DSVerifyKey, ok:= userlib.KeystoreGet(string(publishName))
	if !ok {
		return errors.New(strings.ToTitle("[AppendToFile]: Can't find key in keystore"))
	}
	err = userlib.DSVerify(DSVerifyKey, fileData.Content, fileData.Signatures)
	if err != nil{
		return errors.New(strings.ToTitle("File doesn't match, data breach may happen"))
	}

	//decrpt the content
	json_plainContent := userlib.SymDec(contentKey[:16], fileData.Content)

	var plainContent []byte

	
	err = json.Unmarshal(json_plainContent, &plainContent)

	if err != nil{
		return errors.New(strings.ToTitle("[AppendToFile] Fail to unmarshal the content"))
	}
	//append to the end of content
	plainContent = append(plainContent, content...)

	userdata.StoreFile(filename, plainContent)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}

	cipher_dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}

	username_hash := userlib.Hash([]byte(userdata.Username))
	filename_hash := userlib.Hash([]byte(filename))
	revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
	descriptionData := append([]byte("/dataEncryption/"), revokeCounter...)
	dataKeyPurpose := append(append(username_hash, filename_hash...),  descriptionData...)
	dataKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
	if err != nil{
		return nil, errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(3)"))
	}

	//decrypt and place in struct
	var fileData File
	err = json.Unmarshal(userlib.SymDec(dataKey[:16], cipher_dataJSON), &fileData)
	if err != nil {
		return nil, errors.New("Internal error[LoadFile]: Unable unmarsharl fileData")
	}

	//decrypt the content and return it 
	descriptionContent := append([]byte("/contentEncryption/"), revokeCounter...)
	contentKeyPurpose := append(append(username_hash, filename_hash...),  descriptionContent...)
	contentKey, err:= userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)

	json_content := userlib.SymDec(contentKey[:16], fileData.Content)
	json.Unmarshal(json_content, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
