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
	// "fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username   string            `json:"Username"`
	UserID     userlib.UUID      `json:"UserID"`
	KeyHubs    map[string][]byte `json:"KeyHubs"`
	FileRevoke map[string]int    `json:"FileRevoke"`
	PrivateKey []byte            `json:"PrivateKey"`
	UserMac    []byte            `json:"UserMac"`
	SignKey    []byte
	ShareUser  map[string]map[userlib.UUID]userlib.UUID
	//don't save in dataStore
	InterimData InterimData
}

type InterimData struct {
	MasterKey []byte
	SignKey   userlib.DSSignKey
	DECKey    userlib.PKEDecKey
}

type File struct {
	FileId userlib.UUID
	// Signatures []byte
	Content []byte
}

type Invitation struct {
	InvitationID userlib.UUID
	OwnerID      userlib.UUID
	FileId       userlib.UUID
	// Prev_Invi    userlib.UUID
	Data_key    []byte
	Content_key []byte
	Block_key   []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func formate_checker(username string, password string) (ok bool) {

	if username == "" || len(username) == 0 ||
		password == "" || len(password) == 0 {
		return false
	}

	return true

}

func verifyFileSignature(cipher_dataJSON []byte, filename_hash []byte, dataKey []byte) (filedate []byte, err error) {
	json_fileData_sign := userlib.SymDec(dataKey[:16], cipher_dataJSON)
	json_fileData_hash := json_fileData_sign[0 : len(json_fileData_sign)-256]
	Signatures := json_fileData_sign[len(json_fileData_sign)-256:]

	//split file data and hash
	json_fileData := json_fileData_hash[0 : len(json_fileData_hash)-16]
	sign_name_hash := json_fileData_hash[len(json_fileData_hash)-16:]
	sign_name_uuid, err := uuid.FromBytes(sign_name_hash)
	if err != nil {
		return nil, errors.New(strings.ToTitle("[LoadFile]: can't gen the uuid"))
	}

	sign_full_name, ok := userlib.DatastoreGet(sign_name_uuid)
	if !ok {
		return nil, errors.New(strings.ToTitle("[LoadFile]: Can't find sign_full_name"))
	}

	//check signature
	publishName := append(append(userlib.Hash(sign_full_name), "/"...), filename_hash...)
	DSVerifyKey, ok := userlib.KeystoreGet(string(publishName))
	if !ok {
		publishName = append(append(filename_hash, "/"...), userlib.Hash(sign_full_name)...)
		DSVerifyKey, ok = userlib.KeystoreGet(string(publishName))
		if !ok {
			return nil, errors.New(strings.ToTitle("Can't find the DSverify key in the datastore"))
		}
	}
	err = userlib.DSVerify(DSVerifyKey, userlib.Hash(json_fileData_hash), Signatures)
	if err != nil {
		return nil, errors.New(strings.ToTitle("File doesn't match, data breach may happen"))
	}

	return json_fileData, nil
}

func properly_save_userData(master_key []byte, username_hash []byte, saveble User, DSSignKey userlib.PrivateKeyType) (err error) {

	//remove the interimData, give a empty one to it
	saveble.InterimData = InterimData{}

	json_userdata, err := json.Marshal(saveble)
	if err != nil {
		return errors.New(strings.ToTitle("Internel error: Fail to generate Mashal for json_userdata"))
	}
	// make signature
	Signature, err := userlib.DSSign(DSSignKey, userlib.Hash(json_userdata))
	if err != nil {
		return errors.New(strings.ToTitle("Internel error[properly_save_userData]: Fail to generate Signature"))
	}

	json_userdata = append(json_userdata, Signature...)

	// gen key and encrypt the data store
	purpose_user_data := append(username_hash, "/encryptDataStroage"...)
	enc_data_Store_key, err := userlib.HashKDF(master_key[:16], purpose_user_data)
	if err != nil {
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
	user_uuid, err := uuid.FromBytes(username_hash[:16])
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to create uuid"))
	}

	// make sure there is no same user name
	_, ok := userlib.DatastoreGet(user_uuid)

	if ok {
		return nil, errors.New(strings.ToTitle("username exist, choose another one"))
	}

	//create a password has and drive a key from it
	password_hash := userlib.Hash([]byte(password))
	master_key := userlib.Argon2Key(password_hash, username_hash, 64)

	//combine username hash and password hash gen a user MAC code
	combine_name_password := append(username_hash, password_hash...)
	user_mac, err := userlib.HMACEval(master_key[:16], combine_name_password)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[init]: Fail to create user MAC"))
	}

	// create pub and pri key
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to generate PKEkeys"))
	}

	//publish the personal public key
	userlib.KeystoreSet(username, PKEEncKey)

	//create sign and ver key
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[Init User]: Fail to generate Signkeys"))
	}

	userlib.KeystoreSet(username+"/verify", DSVerifyKey)

	// gen a key from master key for privateKey
	purpose_priKey := append(username_hash, "/privateKey"...)
	pri_dec_key, err := userlib.HashKDF(master_key[:16], purpose_priKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[HashKDF, init]: Fail to generate pri_dec_key"))
	}

	purpose_priSignKey := append(username_hash, "/privateSignKey"...)
	pri_sign_key, err := userlib.HashKDF(master_key[:16], purpose_priSignKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[HashKDF, init]: Fail to generate pri_sign_key"))
	}

	//turn the prikey into Json
	json_pri_enc_key, err := json.Marshal(PKEDecKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to generate Mashal for json_pri_enc_key"))
	}

	json_pri_sign_key, err := json.Marshal(DSSignKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to generate Mashal for json_pri_sign_key"))
	}

	//encrypt it and save it to the userdata struct
	IV := userlib.RandomBytes(16)
	cipherPriKey := userlib.SymEnc(pri_dec_key[:16], IV, json_pri_enc_key)

	IV = userlib.RandomBytes(16)
	cipherSignKey := userlib.SymEnc(pri_sign_key[:16], IV, json_pri_sign_key)
	InterimData := InterimData{
		master_key,
		DSSignKey,
		PKEDecKey,
	}

	userdata := User{
		Username:    username,
		UserID:      user_uuid,
		KeyHubs:     make(map[string][]byte),
		FileRevoke:  make(map[string]int),
		PrivateKey:  cipherPriKey,
		SignKey:     cipherSignKey,
		UserMac:     user_mac,
		ShareUser:   make(map[string]map[userlib.UUID]uuid.UUID),
		InterimData: InterimData,
	}

	err = properly_save_userData(master_key, username_hash, userdata, DSSignKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Fail to save the data in to th data store"))
	}

	//publish the uuid and name pair
	post_uuid, err := uuid.FromBytes(username_hash[48:])
	if err != nil {
		return nil, errors.New(strings.ToTitle("Fail to gen post uuid"))
	}
	userlib.DatastoreSet(post_uuid, []byte(username))

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
	user_uuid, err := uuid.FromBytes(username_hash[:16])
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to create uuid"))
	}

	// make sure there is no same user name
	dataJSONCipher, ok := userlib.DatastoreGet(user_uuid)
	if !ok {
		return nil, errors.New(strings.ToTitle("User doesn't exist"))
	}

	//create a password has and drive a key from it
	password_hash := userlib.Hash([]byte(password))
	master_key := userlib.Argon2Key(password_hash, username_hash, 64)

	// decrypt the data store and make a proper data stor
	purpose2 := append(username_hash, "/encryptDataStroage"...)
	data_Store_key, err := userlib.HashKDF(master_key[:16], purpose2)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[HashKDF]: Fail to generate data_Store_key"))
	}
	dataJSONPlain := userlib.SymDec(data_Store_key[:16], dataJSONCipher)

	dataJSONuser := dataJSONPlain[0 : len(dataJSONPlain)-256]
	Signatures := dataJSONPlain[len(dataJSONPlain)-256:]

	// ?
	err = userlib.DSVerify(userlib.KeystoreGetMap()[username+"/verify"],
		userlib.Hash(dataJSONuser),
		Signatures)

	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error[GET user]: Fail to verify the signature"))
	}

	var userdata User
	err = json.Unmarshal(dataJSONuser, &userdata)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Saved data compromised or password incorrect"))
	}

	//combine username hash and password hash gen a user MAC code
	//and the compare the MACs
	combine_name_password := append(username_hash, password_hash...)
	valid_user_Mac, err := userlib.HMACEval(master_key[:16], combine_name_password)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to create user MAC"))
	}
	res := bytes.Compare(valid_user_Mac, userdata.UserMac)
	if res != 0 {
		return nil, errors.New(strings.ToTitle("Password or username incorrect"))

	}

	// put the sign key there as well
	json_cipher_sign_key := userdata.SignKey
	purpose_priSignKey := append(username_hash, "/privateSignKey"...)
	pri_sign_key, err := userlib.HashKDF(master_key[:16], purpose_priSignKey)
	json_sign_key := userlib.SymDec(pri_sign_key[:16], json_cipher_sign_key)

	var DSSKey userlib.DSSignKey

	err = json.Unmarshal(json_sign_key, &DSSKey)

	//decrypt the PKDecKey
	purpose_priKey := append(username_hash, "/privateKey"...)
	pri_dec_key, err := userlib.HashKDF(master_key[:16], purpose_priKey)
	json_PKDecKey := userlib.SymDec(pri_dec_key[:16], userdata.PrivateKey)

	var PKDecKey userlib.PKEDecKey
	err = json.Unmarshal(json_PKDecKey, &PKDecKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("Internel error: Fail to Unmarshal PKDECKey"))
	}

	//make interim data
	interimData := InterimData{
		master_key,
		DSSKey,
		PKDecKey,
	}

	//attach to the userdata
	userdata.InterimData = interimData

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename))[:16])
	userDataChange := false
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(storageKey)
	username_hash := userlib.Hash([]byte(userdata.Username))
	filename_hash := userlib.Hash([]byte(filename))
	var cipherContent []byte
	var dataKey []byte

	var DSSignKey userlib.DSSignKey
	var DSVerifyKey userlib.DSVerifyKey
	IV := userlib.RandomBytes(16)

	// encrypt the data
	contentBytes, err := json.Marshal(content)
	if ok {

		var contentKey []byte
		// check if is the shared owner or the owner

		var json_pub_key []byte

		publishName := append(append(username_hash, "/"...), filename_hash...)
		DSVerifyKey, ok = userlib.KeystoreGet(string(publishName))
		if ok {
			revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
			description := append([]byte("/contentEncryption/"), revokeCounter...)
			// userlib.DebugMsg("This is the description, of OK", string(description))
			contentKeyPurpose := append(append(username_hash, filename_hash...), description...)
			// userlib.DebugMsg("This is the contentKeyPurpose, of OK", string(contentKeyPurpose))
			contentKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
			if err != nil {
				return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(1)"))
			}

			//make data key
			description = append([]byte("/dataEncryption/"), revokeCounter...)
			dataKeyPurpose := append(append(username_hash, filename_hash...), description...)
			dataKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
			if err != nil {
				return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(3)"))
			}

		} else {

			//shared owner
			publishName = append(append(filename_hash, "/"...), username_hash...)
			DSVerifyKey, ok = userlib.KeystoreGet(string(publishName))

			pushlishName_dataKey := append(publishName, "dataKey"...)
			pushlishName_contenKey := append(publishName, "contentKey"...)
			pushlishName_blockKey := append(publishName, "blockKey"...)

			//make block key
			blockKey := userlib.SymDec(userdata.InterimData.MasterKey[:16],
				userdata.KeyHubs[string(pushlishName_blockKey)])

			//make the data enc key
			dataEncKeyPurpose := []byte("data-key-enc")
			dataEncKeyPurposeHash := userlib.Hash(dataEncKeyPurpose)
			data_enc_key, err := userlib.HashKDF(blockKey[:16], dataEncKeyPurposeHash)
			if err != nil {
				return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(4)"))
			}
			// //make the content enc key
			contentEncPurpose := []byte("content-key-enc")
			contentEncPurposeHash := userlib.Hash(contentEncPurpose)
			content_enc_key, err := userlib.HashKDF(blockKey[:16], contentEncPurposeHash)
			if err != nil {
				return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(5)"))
			}
			// make the data key and contentKey
			dataKey = userlib.SymDec(data_enc_key[:16], userdata.KeyHubs[string(pushlishName_dataKey)])
			contentKey = userlib.SymDec(content_enc_key[:16], userdata.KeyHubs[string(pushlishName_contenKey)])

		}
		//make the cipher content
		cipherContent = userlib.SymEnc(contentKey[:16], IV, contentBytes)

		// get the DSsKey
		json_pub_key, err = json.Marshal(DSVerifyKey)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pub key)"))
		}
		//decrpt the pri_key
		cipher_json_pri_key := userdata.KeyHubs[string(json_pub_key)]
		priKeyPurpose := append(append(username_hash, filename_hash...), "/privateKeyEnc"...)
		key_of_priKey, err := userlib.HashKDF(userdata.InterimData.MasterKey[:16], priKeyPurpose)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to HashKDP pri key(1)"))
		}

		json_pri_key := userlib.SymDec(key_of_priKey[:16], cipher_json_pri_key)

		// unmarshal the DSskey
		err = json.Unmarshal(json_pri_key, &DSSignKey)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to unmarsh priv key)"))
		}

	} else {
		description := append([]byte("/contentEncryption/revokeCounter"), byte(0))
		// userlib.DebugMsg("This is the description, of not OK", string(description))
		contentKeyPurpose := append(append(username_hash, filename_hash...), description...)
		// userlib.DebugMsg("This is the contentKeyPurpose, of not OK", string(contentKeyPurpose))
		contentKey, err := userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(2)"))
		}
		//userlib.DebugMsg("This is the content key, of not OK", string(contentKey))
		cipherContent = userlib.SymEnc(contentKey[:16], IV, contentBytes)

		//make data key
		description = append([]byte("/dataEncryption/revokeCounter"), byte(0))
		dataKeyPurpose := append(append(username_hash, filename_hash...), description...)
		dataKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(3)"))
		}

		DSSignKey, DSVerifyKey, err = userlib.DSKeyGen()
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen Signatures(1)"))
		}

		// publish the new pub key
		publishName := append(append(username_hash, "/"...), filename_hash...)
		userlib.KeystoreSet(string(publishName), DSVerifyKey)

		//add pri-pub key pair to the user data
		json_pub_key, err := json.Marshal(DSVerifyKey)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pub key)"))
		}
		json_pri_key, err := json.Marshal(DSSignKey)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pri key)"))
		}

		//encrypt the private key
		priKeyPurpose := append(append(username_hash, filename_hash...), "/privateKeyEnc"...)
		key_of_priKey, err := userlib.HashKDF(userdata.InterimData.MasterKey[:16], priKeyPurpose)
		if err != nil {
			return errors.New(strings.Title("Internal Error[StoreFile]: Fail to HashKDP pri key)"))
		}

		IV = userlib.RandomBytes(16)
		cipher_pri_key := userlib.SymEnc(key_of_priKey[:16], IV, json_pri_key)

		//add the the data
		userdata.KeyHubs[string(json_pub_key)] = cipher_pri_key
		userdata.FileRevoke[string(filename_hash)] = 0
		userDataChange = true
	}

	//make the file data
	fileData := File{
		FileId:  storageKey,
		Content: cipherContent,
	}

	//make the cipher file data and save it
	json_fileData, err := json.Marshal(fileData)
	if err != nil {
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen Marshal"))
	}

	//append the 16 bytes of hash
	json_fileData = append(json_fileData, username_hash[48:]...)

	hash_json_fileData := userlib.Hash(json_fileData)
	//make a Signatures from the whole block
	Signatures, err := userlib.DSSign(DSSignKey, hash_json_fileData)
	if err != nil {
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen Signatures(2)"))
	}

	//combine the signature into the saving data
	json_fileData = append(json_fileData, Signatures...)

	IV = userlib.RandomBytes(16)
	cipherFileData := userlib.SymEnc(dataKey[:16], IV, json_fileData)
	userlib.DatastoreSet(storageKey, cipherFileData)

	// save the data
	if userDataChange {
		properly_save_userData(userdata.InterimData.MasterKey, username_hash, *userdata, userdata.InterimData.SignKey)
	}
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename))[:16])
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
	} else {

		publishName := append(append(username_hash, "/"...), filename_hash...)
		_, ok = userlib.KeystoreGet(string(publishName))

		if ok {
			revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
			data_description := append([]byte("/dataEncryption/"), revokeCounter...)
			dataKeyPurpose := append(append(username_hash, filename_hash...), data_description...)
			dataKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
			if err != nil {
				return errors.New(strings.ToTitle("[AppendToFile]: fail to HashKDF(1)"))
			}

			content_description := append([]byte("/contentEncryption/"), revokeCounter...)
			contentKeyPurpose := append(append(username_hash, filename_hash...), content_description...)
			contentKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
			// userlib.DebugMsg("This is the content key, of not append store", string(contentKey))
			if err != nil {
				return errors.New(strings.ToTitle("[AppendToFile]: fail to HashKDF(2)"))
			}

		} else {
			publishName := append(append(filename_hash, "/"...), username_hash...)
			_, ok = userlib.KeystoreGet(string(publishName))
			if !ok {
				return errors.New(strings.Title("No such a user"))
			}
			pushlishName_dataKey := append(publishName, "dataKey"...)
			pushlishName_contenKey := append(publishName, "contentKey"...)
			pushlishName_blockKey := append(publishName, "blockKey"...)

			//make block key
			blockKey := userlib.SymDec(userdata.InterimData.MasterKey[:16],
				userdata.KeyHubs[string(pushlishName_blockKey)])

			//make the data enc key
			dataEncKeyPurpose := []byte("data-key-enc")
			dataEncKeyPurposeHash := userlib.Hash(dataEncKeyPurpose)
			data_enc_key, err := userlib.HashKDF(blockKey[:16], dataEncKeyPurposeHash)
			if err != nil {
				return errors.New(strings.Title("Internal Error[AppendToFile]: Fail to gen HashKDF(4)"))
			}
			// //make the content enc key
			contentEncPurpose := []byte("content-key-enc")
			contentEncPurposeHash := userlib.Hash(contentEncPurpose)
			content_enc_key, err := userlib.HashKDF(blockKey[:16], contentEncPurposeHash)
			if err != nil {
				return errors.New(strings.Title("Internal Error[AppendToFile]: Fail to gen HashKDF(5)"))
			}
			// make the data key and contentKey
			dataKey = userlib.SymDec(data_enc_key[:16], userdata.KeyHubs[string(pushlishName_dataKey)])
			contentKey = userlib.SymDec(content_enc_key[:16], userdata.KeyHubs[string(pushlishName_contenKey)])
		}

	}

	//check if is the owner or not then do the enc or dec
	// make a key to decrpt the data
	json_fileData, err := verifyFileSignature(cipher_json_fileData, filename_hash, dataKey)
	err = json.Unmarshal(json_fileData, &fileData)
	if err != nil {
		return errors.New(strings.ToTitle("[AppendToFile]: fail to unmarshal"))
	}

	//decrpt the content
	json_plainContent := userlib.SymDec(contentKey[:16], fileData.Content)

	var plainContent []byte

	err = json.Unmarshal(json_plainContent, &plainContent)

	if err != nil {
		return errors.New(strings.ToTitle("[AppendToFile] Fail to unmarshal the content"))
	}
	//append to the end of content
	plainContent = append(plainContent, content...)

	userdata.StoreFile(filename, plainContent)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename))[:16])
	if err != nil {
		return nil, err
	}

	cipher_dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	var dataKey []byte
	var contentKey []byte
	var fileData File

	username_hash := userlib.Hash([]byte(userdata.Username))
	filename_hash := userlib.Hash([]byte(filename))

	publishName := append(append(username_hash, "/"...), filename_hash...)
	_, ok = userlib.KeystoreGet(string(publishName))

	if ok {
		revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
		descriptionData := append([]byte("/dataEncryption/"), revokeCounter...)
		dataKeyPurpose := append(append(username_hash, filename_hash...), descriptionData...)
		dataKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
		if err != nil {
			return nil, errors.New(strings.Title("Internal Error[LoadFile]: Fail to gen HashKDF(3)"))
		}

		//decrypt and place in struct

		//decrypt the content and return it
		descriptionContent := append([]byte("/contentEncryption/"), revokeCounter...)
		contentKeyPurpose := append(append(username_hash, filename_hash...), descriptionContent...)
		contentKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)

	} else {
		publishName := append(append(filename_hash, "/"...), username_hash...)
		_, ok = userlib.KeystoreGet(string(publishName))
		if !ok {
			return nil, errors.New(strings.Title("No such a user"))
		}
		pushlishName_dataKey := append(publishName, "dataKey"...)
		pushlishName_contenKey := append(publishName, "contentKey"...)
		pushlishName_blockKey := append(publishName, "blockKey"...)

		//make block key
		blockKey := userlib.SymDec(userdata.InterimData.MasterKey[:16],
			userdata.KeyHubs[string(pushlishName_blockKey)])

		//make the data enc key
		dataEncKeyPurpose := []byte("data-key-enc")
		dataEncKeyPurposeHash := userlib.Hash(dataEncKeyPurpose)
		data_enc_key, err := userlib.HashKDF(blockKey[:16], dataEncKeyPurposeHash)
		if err != nil {
			return nil, errors.New(strings.Title("Internal Error[LoadFile]: Fail to gen HashKDF(4)"))
		}
		// //make the content enc key
		contentEncPurpose := []byte("content-key-enc")
		contentEncPurposeHash := userlib.Hash(contentEncPurpose)
		content_enc_key, err := userlib.HashKDF(blockKey[:16], contentEncPurposeHash)
		if err != nil {
			return nil, errors.New(strings.Title("Internal Error[LoadFile]: Fail to gen HashKDF(5)"))
		}
		// make the data key and contentKey
		dataKey = userlib.SymDec(data_enc_key[:16], userdata.KeyHubs[string(pushlishName_dataKey)])
		contentKey = userlib.SymDec(content_enc_key[:16], userdata.KeyHubs[string(pushlishName_contenKey)])

	}

	json_fileData, err := verifyFileSignature(cipher_dataJSON, filename_hash, dataKey)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(json_fileData, &fileData)
	if err != nil {
		return nil, errors.New("Internal error[LoadFile]: Unable unmarsharl fileData")
	}

	json_content := userlib.SymDec(contentKey[:16], fileData.Content)
	json.Unmarshal(json_content, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	username_hash := userlib.Hash([]byte(userdata.Username))
	// recipitent_hash := userlib.Hash([]byte(recipientUsername))
	filename_hash := userlib.Hash([]byte(filename))
	//check if the file exisit
	file_id, err := uuid.FromBytes(filename_hash[:16])
	if err != nil {
		return uuid.Nil, errors.New(strings.Title("Internal error[CreateInvitation]: fail to generate file_id"))
	}

	_, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return uuid.Nil, errors.New(strings.Title("Internal error[CreateInvitation]: no such a file"))
	}

	PKYEncKey, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		return uuid.Nil, errors.New(strings.Title("Internal error[CreateInvitation]: recipientUsername don't exsit"))
	}

	// assign name to Invitation
	Invitation_name := userdata.Username + "/" + filename + "/" + recipientUsername
	Invitation_name_hash := userlib.Hash([]byte(Invitation_name))
	Invitation_id, err := uuid.FromBytes(Invitation_name_hash[:16])
	if err != nil {
		return uuid.Nil, errors.New(strings.Title("Internal error[CreateInvitation]: fail to generate Invitation_id"))
	}

	publishName := append(append(username_hash, "/"...), filename_hash...)
	_, ok = userlib.KeystoreGet(string(publishName))

	var dataKey []byte
	var contentKey []byte
	var blockKey []byte
	if ok {
		//make data key
		revokeCounter := append([]byte("revokeCounter"), byte(userdata.FileRevoke[string(filename_hash)]))
		description := append([]byte("/dataEncryption/"), revokeCounter...)
		dataKeyPurpose := append(append(username_hash, filename_hash...), description...)
		dataKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], dataKeyPurpose)
		if err != nil {
			return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to gen HashKDF(1)"))
		}

		//make content key
		description = append([]byte("/contentEncryption/"), revokeCounter...)
		// userlib.DebugMsg("This is the description, of OK", string(description))
		contentKeyPurpose := append(append(username_hash, filename_hash...), description...)
		// userlib.DebugMsg("This is the contentKeyPurpose, of OK", string(contentKeyPurpose))
		contentKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], contentKeyPurpose)
		if err != nil {
			return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to gen HashKDF(2)"))
		}

		//make a block key
		description = append([]byte("/block/"), revokeCounter...)
		blockKeyPurpose := append(append(username_hash, filename_hash...), description...)
		blockKeyPurposeHash := userlib.Hash(blockKeyPurpose)
		blockKey, err = userlib.HashKDF(userdata.InterimData.MasterKey[:16], blockKeyPurposeHash)
		if err != nil {
			return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to gen HashKDF(2)"))
		}

	} else {
		//shared users

		publishName = append(append(filename_hash, "/"...), username_hash...)
		_, ok = userlib.KeystoreGet(string(publishName))

		pushlishName_dataKey := append(publishName, "dataKey"...)
		pushlishName_contenKey := append(publishName, "contentKey"...)
		pushlishName_blockKey := append(publishName, "blockKey"...)

		//make block key
		blockKey = userlib.SymDec(userdata.InterimData.MasterKey[:16],
			userdata.KeyHubs[string(pushlishName_blockKey)])

		//make the data enc key
		dataEncKeyPurpose := []byte("data-key-enc")
		dataEncKeyPurposeHash := userlib.Hash(dataEncKeyPurpose)
		data_enc_key, err := userlib.HashKDF(blockKey[:16], dataEncKeyPurposeHash)
		if err != nil {
			return uuid.Nil, errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(4)"))
		}
		// //make the content enc key
		contentEncPurpose := []byte("content-key-enc")
		contentEncPurposeHash := userlib.Hash(contentEncPurpose)
		content_enc_key, err := userlib.HashKDF(blockKey[:16], contentEncPurposeHash)
		if err != nil {
			return uuid.Nil, errors.New(strings.Title("Internal Error[StoreFile]: Fail to gen HashKDF(5)"))
		}
		// make the data key and contentKey
		dataKey = userlib.SymDec(data_enc_key[:16], userdata.KeyHubs[string(pushlishName_dataKey)])
		contentKey = userlib.SymDec(content_enc_key[:16], userdata.KeyHubs[string(pushlishName_contenKey)])

	}

	//derive data enc key
	dataEncKeyPurpose := []byte("data-key-enc")
	dataEncKeyPurposeHash := userlib.Hash(dataEncKeyPurpose)
	data_enc_key, err := userlib.HashKDF(blockKey[:16], dataEncKeyPurposeHash)

	//derive content enc key
	contentEncPurpose := []byte("content-key-enc")
	contentEncPurposeHash := userlib.Hash(contentEncPurpose)
	content_enc_key, err := userlib.HashKDF(blockKey[:16], contentEncPurposeHash)

	//enc data key and content key and block key
	IV := userlib.RandomBytes(16)
	cipherDataKey := userlib.SymEnc(data_enc_key[:16], IV, dataKey)

	IV = userlib.RandomBytes(16)
	cipherContentKey := userlib.SymEnc(content_enc_key[:16], IV, contentKey)

	cipherblockKey, err := userlib.PKEEnc(PKYEncKey, blockKey)
	if err != nil {
		return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to PKEEnc"))
	}

	//put then into the Invitation
	Invitation := Invitation{
		Invitation_id,
		userdata.UserID,
		file_id,
		cipherDataKey,
		cipherContentKey,
		cipherblockKey,
	}

	//encrypt the data block
	data_block, err := json.Marshal(Invitation)
	if err != nil {
		return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to marshal"))
	}
	IV = userlib.RandomBytes(16)
	cipherDataBlock := userlib.SymEnc(blockKey[:16], IV, data_block)
	if err != nil {
		return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to Public encrpt"))
	}

	//make signature
	Signature, err := userlib.DSSign(userdata.InterimData.SignKey, userlib.Hash(cipherDataBlock))
	if err != nil {
		return uuid.Nil, errors.New(strings.Title("Internal Error[CreateInvitation]: Fail to sign"))
	}

	//create the block
	cipherDataBlock = append(cipherDataBlock, cipherblockKey...)
	cipherDataBlock = append(cipherDataBlock, Signature...)

	userlib.DatastoreSet(Invitation_id, cipherDataBlock)

	//update the user
	userdata.ShareUser[recipientUsername] = map[uuid.UUID]uuid.UUID{file_id: Invitation_id}
	properly_save_userData(userdata.InterimData.MasterKey, username_hash, *userdata, userdata.InterimData.SignKey)

	return Invitation_id, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	username_hash := userlib.Hash([]byte(userdata.Username))
	// recipitent_hash := userlib.Hash([]byte(recipientUsername))
	filename_hash := userlib.Hash([]byte(filename))
	//check if the file exisit
	file_id, err := uuid.FromBytes(filename_hash[:16])
	if err != nil {
		return errors.New(strings.Title("Internal error[AcceptInvitation]: fail to generate file_id"))
	}

	_, ok := userlib.DatastoreGet(file_id)
	if !ok {
		return errors.New(strings.Title("Internal error[AcceptInvitation]: no such a file"))
	}

	jsoncipherDataBlock, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("[AcceptInvitation]: No such a invitation"))
	}

	jsoncipherData := jsoncipherDataBlock[0 : len(jsoncipherDataBlock)-(256*2)]
	cipherBlockKey := jsoncipherDataBlock[len(jsoncipherDataBlock)-(256*2) : len(jsoncipherDataBlock)-256]
	Signature := jsoncipherDataBlock[len(jsoncipherDataBlock)-256:]

	// ?
	//verify the signature
	DSvK := userlib.KeystoreGetMap()[senderUsername+"/verify"]
	err = userlib.DSVerify(DSvK,
		userlib.Hash(jsoncipherData),
		Signature)
	if err != nil {
		return errors.New(strings.ToTitle("[AcceptInvitation]: Fail to verify"))
	}

	//make the block key
	blockKey, err := userlib.PKEDec(userdata.InterimData.DECKey, cipherBlockKey)
	if err != nil {
		return errors.New(strings.ToTitle("[AcceptInvitation]: Fail to PKEDec"))
	}

	//decrypt the invitation
	jsonData := userlib.SymDec(blockKey[:16], jsoncipherData)

	//build the invitation
	var Invitation Invitation
	err = json.Unmarshal(jsonData, &Invitation)
	if err != nil {
		return errors.New(strings.ToTitle("[AcceptInvitation]: Fail to unmarshal"))
	}

	//enc the block key with the master key
	IV := userlib.RandomBytes(16)
	cipherBlockKey = userlib.SymEnc(userdata.InterimData.MasterKey[:16], IV, blockKey)

	//make the data enc key
	publishName := append(append(filename_hash, "/"...), username_hash...)
	pushlishName_dataKey := append(publishName, "dataKey"...)
	pushlishName_contenKey := append(publishName, "contentKey"...)
	pushlishName_blockKey := append(publishName, "blockKey"...)
	userdata.KeyHubs[string(pushlishName_dataKey)] = Invitation.Data_key
	userdata.KeyHubs[string(pushlishName_contenKey)] = Invitation.Content_key
	userdata.KeyHubs[string(pushlishName_blockKey)] = cipherBlockKey

	//gen keys for file signature
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return errors.New(strings.Title("[Accept Invitation]: fail to gen keys"))
	}

	userlib.KeystoreSet(string(publishName), DSVerifyKey)

	json_pub_key, err := json.Marshal(DSVerifyKey)
	if err != nil {
		return errors.New(strings.Title("[Accept Invitation]: Fail to marsh pub key)"))
	}

	json_pri_key, err := json.Marshal(DSSignKey)
	if err != nil {
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to marsh pri key)"))
	}

	//encrypt the private key
	priKeyPurpose := append(append(username_hash, filename_hash...), "/privateKeyEnc"...)
	key_of_priKey, err := userlib.HashKDF(userdata.InterimData.MasterKey[:16], priKeyPurpose)
	if err != nil {
		return errors.New(strings.Title("Internal Error[StoreFile]: Fail to HashKDP pri key)"))
	}
	//
	IV = userlib.RandomBytes(16)
	cipher_pri_key := userlib.SymEnc(key_of_priKey[:16], IV, json_pri_key)
	userdata.KeyHubs[string(json_pub_key)] = cipher_pri_key

	//update the user data
	err = properly_save_userData(userdata.InterimData.MasterKey,
		username_hash,
		*userdata,
		userdata.InterimData.SignKey)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	username_hash := userlib.Hash([]byte(userdata.Username))
	filename_hash := userlib.Hash([]byte(filename))
	publishName := append(append(username_hash, "/"...), filename_hash...)
	_, ok := userlib.KeystoreGet(string(publishName))
	if !ok {
		return errors.New(strings.Title("File dones't belong to current user"))
	}

	// check if it is the real reciver
	if _, ok := userdata.ShareUser[recipientUsername]; !ok {
		return errors.New(strings.Title("is no the share user"))
	}

	content, err := userdata.LoadFile(filename)
	if err != nil {
		return errors.New(strings.Title("Can't load file"))
	}

	//reset the revoke
	userdata.FileRevoke[string(filename_hash)] += 1

	//reset the file, as the revoke change, the key will change as well
	userdata.StoreFile(filename, content)

	//save the user data
	properly_save_userData(userdata.InterimData.MasterKey,
		username_hash,
		*userdata, userdata.InterimData.SignKey)

	//make other users accessiable?
	return nil
}
