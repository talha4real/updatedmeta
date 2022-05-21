package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	bin "github.com/gagliardetto/binary"

	nftcandymachinev2 "github.com/gagliardetto/metaplex-go/clients/nft-candy-machine-v2"
	nftcandymachinev2withWhitelist "github.com/talha4real/metaplexgo/clients/nft-candy-machine-v2"
	token_metadata "github.com/gagliardetto/metaplex-go/clients/token-metadata"
	"github.com/gagliardetto/solana-go"
	atok "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

var candyMachineV2ProgramID = solana.MustPublicKeyFromBase58("cndy3Z4yapfJBmL3ShUp5exZKqR3z33thTzeNMm2gRZ")

func startMenu() {
	startCandyMachineV2Minting()
}

func loadCSVFile(dir string) ([][]string, error) {
	data, err := ioutil.ReadFile(dir)
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(strings.NewReader(string(data)))
	file, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	return file[1:], nil
}

func startMint(cmid solana.PublicKey, key string, rpc string, bump uint8, cretr solana.PublicKey) {
	//candyMachineAddress := solana.MustPublicKeyFromBase58(cmid)
	user, err := solana.PrivateKeyFromBase58(key)
	// user, err := solana.PrivateKeyFromSolanaKeygenFile("./id.json")
	if err != nil {
		panic(err)
	}

	go strt(cmid,
		user,
		rpc,
		bump,
		cretr)

}
func strt(cmid solana.PublicKey, user solana.PrivateKey, rpc string, bump uint8, cretr solana.PublicKey) {

	// for true {
	sig, err := mint(
		cmid,
		user,
		rpc,
		bump,
		cretr,
	)

	if err != nil {

		fmt.Printf("\nFailed : %s ", err)
		fmt.Print(sig)
	} else {

	}
	//}
}
func startTaskByCsvName(filename string) {
	file2, err := loadCSVFile("./CandyMachineV2/" + filename)
	if err != nil {
		fmt.Println(err)
	}
	totalTasks := 0
	for i := 0; i < len(file2); i++ {
		candyMachineUserInput := file2[i][0]
		privateKeyUserInput := file2[i][1]
		rpcUrlUserInput := file2[i][2]
		taskAmountUserInputFirst := file2[i][3]
		taskAmountUserInput, err := strconv.ParseInt(taskAmountUserInputFirst, 0, 64)
		if err != nil {
			fmt.Println(err)
		}

		candyMachineAddress := solana.MustPublicKeyFromBase58(candyMachineUserInput)
		candyMachineCreator, creatorBump, err := getCandyMachineCreator(candyMachineAddress)

		for a := 0; a < int(taskAmountUserInput); a++ {
			totalTasks++
			time.Sleep(50 * time.Millisecond)
			go startMint(candyMachineAddress, privateKeyUserInput, rpcUrlUserInput, creatorBump, candyMachineCreator)
			fmt.Println("[Task: " + strconv.Itoa(totalTasks) + "]" + "[CandyMachine:" + candyMachineUserInput + "]")
		}
		// wg.Wait()
		fmt.Scanln()
	}
}
func startCandyMachineV2Minting() {
	startTaskByCsvName("Task_01.csv")
}

func main() {
	// testMint()
	startMenu()
}

// ok we need csv tasks in folder, i will send you
// ok this task system i made is good for users with selectin and stuff so just call the mint function from there with the 4 things, and in the mint function it should say in the print statements which task is it like [task1] => Sending tx, yk
//  ok
var remainingAccounts []solana.AccountMeta
var cleanupInstructions []solana.Instruction
var userPayingAccountAddress solana.PublicKey

func mint(
	candyMachineAddress solana.PublicKey,
	userKeyPair solana.PrivateKey,
	crpc string,
	cbump uint8,
	creator solana.PublicKey,
) (string, error) {
	nftcandymachinev2.SetProgramID(candyMachineV2ProgramID)

	mint := solana.NewWallet()

	client := rpc.New(crpc)
	// client := rpc.New("crpc")

	userTokenAccountAddress, err := getTokenWallet(userKeyPair.PublicKey(), mint.PublicKey())
	if err != nil {
		return "userTokenAccountAddress", err
	}

	candyMachineRaw, err := client.GetAccountInfo(context.TODO(), candyMachineAddress)
	if err != nil {
		return "userTokenAccountAddress", err
	}

	signers := []solana.PrivateKey{mint.PrivateKey, userKeyPair}

	min, err := client.GetMinimumBalanceForRentExemption(context.TODO(), token.MINT_SIZE, rpc.CommitmentFinalized)
	if err != nil {
		return "userTokenAccountAddress", err
	}

	dec := bin.NewBorshDecoder(candyMachineRaw.Value.Data.GetBinary())
	var cm nftcandymachinev2.CandyMachine
	err = dec.Decode(&cm)
	if err != nil {
		return "solana.Signature{}", err
	}
	// fmt.Println(cm)

	// if cm.Data.WhitelistMintSettings != nil {
	// 	whitelistBurnAuthority := solana.NewWallet()

	// 	remainingAccounts = append(remainingAccounts, *solana.NewAccountMeta())

	// } else {

	// }

	// if cm.TokenMint != nil {
	// 	userPayingAccountAddress, err = getTokenWallet(*cm.TokenMint, userKeyPair.PublicKey())
	// 	if err != nil {
	// 		return solana.Signature{}, err
	// 	}
	// } else {
	// 	userPayingAccountAddress = userKeyPair.PublicKey()
	// }

	var instructions []solana.Instruction
	instructions = append(instructions,
		system.NewCreateAccountInstructionBuilder().
			SetOwner(token.ProgramID).
			SetNewAccount(mint.PublicKey()).
			SetSpace(token.MINT_SIZE).
			SetFundingAccount(userKeyPair.PublicKey()).
			SetLamports(min).
			Build(),

		token.NewInitializeMint2InstructionBuilder().
			SetMintAccount(mint.PublicKey()).
			SetDecimals(0).
			SetMintAuthority(userKeyPair.PublicKey()).
			SetFreezeAuthority(userKeyPair.PublicKey()).
			Build(),

		atok.NewCreateInstructionBuilder().
			SetPayer(userKeyPair.PublicKey()).
			SetWallet(userKeyPair.PublicKey()).
			SetMint(mint.PublicKey()).
			Build(),

		token.NewMintToInstructionBuilder().
			SetMintAccount(mint.PublicKey()).
			SetDestinationAccount(userTokenAccountAddress).
			SetAuthorityAccount(userKeyPair.PublicKey()).
			SetAmount(1).
			Build(),
	)

	metadataAddress, err := getMetadata(mint.PublicKey())
	if err != nil {
		return "solana.Signature{}", err
	}
	masterEdition, err := getMasterEdition(mint.PublicKey())
	if err != nil {
		return "solana.Signature{}", err
	}
	// candyMachineCreator, creatorBump, err := getCandyMachineCreator(candyMachineAddress)
	if err != nil {
		return "solana.Signature{}", err
	}

	//Lets try to add TokenMint

	//Token Mint

	// if cm.TokenMint != nil {
	// 	fmt.Println("We have TokenMint")
	// 	transferAuthority := solana.NewWallet()
	// 	signers = append(signers, transferAuthority.PrivateKey)

	// 	keys := []solana.AccountMeta{
	// 		{
	// 			PublicKey:  userPayingAccountAddress,
	// 			IsSigner:   true,
	// 			IsWritable: true,
	// 		},
	// 		{
	// 			PublicKey:  transferAuthority.PublicKey(),
	// 			IsSigner:   true,
	// 			IsWritable: true,
	// 		},
	// 	}

	// 	// remainingInstructions = append(remainingInstructions, [keys], )

	// 	instructions = append(instructions,
	// 		token.NewApproveInstructionBuilder().
	// 			SetAmount(cm.Data.Price).
	// 			SetSourceAccount(userKeyPair.PublicKey()).
	// 			SetDelegateAccount(transferAuthority.PublicKey()).
	// 			SetOwnerAccount(solana.SPLAssociatedTokenAccountProgramID, userKeyPair.PublicKey()).
	// 			Build(),
	// 	)

	// 	cleanupInstructions = append(cleanupInstructions,
	// 		token.NewRevokeInstructionBuilder().
	// 			SetOwnerAccount(token_metadata.ProgramID).
	// 			SetSourceAccount(userPayingAccountAddress).
	// 			Build())

	// 	fmt.Println(keys)

	// }


	if cm.Data.WhitelistMintSettings != nil {
		mint2 := new PublicKey(cm.Data.WhitelistMintSettings.mint)

		whitelistToken:= getAtaForMint(mint,userKeyPair.PublicKey)
		whitelistToken = whitelistToken[0]


		whitelistBurnAuthority := solana.NewWallet()
		

		
		instructions = append(instructions,
			nftcandymachinev2.NewMintNftInstructionBuilder().
				SetCreatorBump(cbump).
				SetCandyMachineAccount(candyMachineAddress).
				SetCandyMachineCreatorAccount(creator).
				SetPayerAccount(userKeyPair.PublicKey()).
				SetWalletAccount(cm.Wallet).
				SetMintAccount(mint.PublicKey()).
				SetMetadataAccount(metadataAddress).
				SetMasterEditionAccount(masterEdition).
				SetMintAuthorityAccount(userKeyPair.PublicKey()).
				SetUpdateAuthorityAccount(userKeyPair.PublicKey()).
				SetTokenMetadataProgramAccount(token_metadata.ProgramID).
				SetTokenProgramAccount(token.ProgramID).
				SetSystemProgramAccount(system.ProgramID).
				SetRentAccount(solana.SysVarRentPubkey).
				SetClockAccount(solana.SysVarClockPubkey).
				SetRecentBlockhashesAccount(solana.SysVarRecentBlockHashesPubkey).
				SetInstructionSysvarAccountAccount(solana.SysVarInstructionsPubkey).
				SetWhiteListToken(whitelistToken).
				SetMintWhitelist(mint2).
				SetBurnAuthority(whitelistBurnAuthority.PublicKey()).
				Build(),
		)

		signers = append(signers,whitelistBurnAuthority)


		existsRaw, err := client.GetAccountInfo(context.TODO(), whitelistToken)
		if err != nil {
			return "whitelistToken", err
		}

		dec2 := bin.NewBorshDecoder(existsRaw.Value.Data.GetBinary())
		var exists nftcandymachinev2.CandyMachine
		err = dec2.Decode(&exists)
		if err != nil {
			return "solana.Signature{}", err
		}

		if exists!= nil {

			instructions = append(instructions,
				token.NewApproveInstructionBuilder().
					SetAmount(1).
					SetSourceAccount(userKeyPair.PublicKey()).
					SetDelegateAccount(whitelistBurnAuthority.PublicKey()).
					SetOwnerAccount(solana.TokenProgramID).
					Build(),
			)

		}


	} else {
		instructions = append(instructions,
			nftcandymachinev2.NewMintNftInstructionBuilder().
				SetCreatorBump(cbump).
				SetCandyMachineAccount(candyMachineAddress).
				SetCandyMachineCreatorAccount(creator).
				SetPayerAccount(userKeyPair.PublicKey()).
				SetWalletAccount(cm.Wallet).
				SetMintAccount(mint.PublicKey()).
				SetMetadataAccount(metadataAddress).
				SetMasterEditionAccount(masterEdition).
				SetMintAuthorityAccount(userKeyPair.PublicKey()).
				SetUpdateAuthorityAccount(userKeyPair.PublicKey()).
				SetTokenMetadataProgramAccount(token_metadata.ProgramID).
				SetTokenProgramAccount(token.ProgramID).
				SetSystemProgramAccount(system.ProgramID).
				SetRentAccount(solana.SysVarRentPubkey).
				SetClockAccount(solana.SysVarClockPubkey).
				SetRecentBlockhashesAccount(solana.SysVarRecentBlockHashesPubkey).
				SetInstructionSysvarAccountAccount(solana.SysVarInstructionsPubkey).
				Build(),
		)
	}


	
	
	// for {

	go sendTransaction(
		client,
		userKeyPair,
		instructions,
		signers,
	)
	//}

	return "Good", nil
}

var slots []uint64

var tpus []*string

func sendTransaction(
	client *rpc.Client,
	wallet solana.PrivateKey,
	instructions []solana.Instruction,
	signers []solana.PrivateKey,

) (string, error) {

	recent, err := client.GetRecentBlockhash(context.TODO(), rpc.CommitmentFinalized)
	if err != nil {
		return "solana.Signature{}", err
	}

	tx, err := solana.NewTransaction(
		instructions,
		recent.Value.Blockhash,
		solana.TransactionPayer(wallet.PublicKey()),
	)

	_, err = tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		for _, candidate := range signers {
			if candidate.PublicKey().Equals(key) {
				return &candidate
			}
		}
		return nil
	})
	if err != nil {
		return "solana.Signature{}", err
	}
	// spew.Dump(tx)

	if err != nil {
		return "solana.Signature{}", err
	}
	// Or just send the transaction WITHOUT waiting for confirmation:
	if err != nil {
		fmt.Println("RPC not responding")
	}

	// tx64, err := tx.ToBase64()
	// txRaw, err := base64.StdEncoding.DecodeString(tx64)

	res, err := client.SimulateTransaction(
		context.TODO(),
		tx,
	)

	// sig, err := client.SendRawTransactionWithOpts(
	// 	context.TODO(),
	// 	txRaw,
	// 	true,
	// 	rpc.CommitmentProcessed,
	// )
	if err != nil {
		fmt.Println("Transaction Expected to Fail")
		fmt.Println(res)
	} else {

		sig, err := client.SendTransaction(
			context.TODO(),
			tx,
		)
		fmt.Println(sig)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Transaction Sent With Sig:")
			fmt.Println(sig)
		}
		//fmt.Printf("\n" + "\nTotal txns Sent: " + strconv.Itoa(numOfTransactions))

	}
	return "Raw tx here", nil
	// return client.SendRawTransactionWithOpts(
	// 	context.TODO(),
	// 	txRaw,
	// 	true,
	// 	rpc.CommitmentProcessed,
	// )
}

func udpflood(TRANSACTION []byte, tpuClientIP string) {
	fmt.Println(tpuClientIP)
	conn, err := net.Dial("udp", tpuClientIP)
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()
	log.Printf("[*] Start flooding %s\n", tpuClientIP)
	for i := 0; i < 100; i++ {
		// go func() {
		// 	for {
		conn.Write((TRANSACTION))
		// 	}
		// }()

	}
}

func getTokenWallet(wallet solana.PublicKey, mint solana.PublicKey) (solana.PublicKey, error) {
	addr, _, err := solana.FindProgramAddress(
		[][]byte{
			wallet.Bytes(),
			solana.TokenProgramID.Bytes(),
			mint.Bytes(),
		},
		solana.SPLAssociatedTokenAccountProgramID,
	)
	return addr, err
}

func getCandyMachineCreator(candyMachineAddress solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress(
		[][]byte{
			[]byte("candy_machine"),
			candyMachineAddress.Bytes(),
		},
		candyMachineV2ProgramID,
	)
}

func getMetadata(mint solana.PublicKey) (solana.PublicKey, error) {
	addr, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("metadata"),
			token_metadata.ProgramID.Bytes(),
			mint.Bytes(),
		},
		token_metadata.ProgramID,
	)

	return addr, err
}
func getAtaForMint(mint solana.PublicKey, buyer solana.PublicKey) (solana.PublicKey, error) {
	addr, _, err := solana.FindProgramAddress(
		[][]byte{
			buyer.Bytes(),
			// buyer.Bytes, //add Here token program id
			mint.Bytes(),
		},
		token_metadata.ProgramID, //Add Associated program id here
	)

	return addr, err
}

func getMasterEdition(mint solana.PublicKey) (solana.PublicKey, error) {
	addr, _, err := solana.FindProgramAddress(
		[][]byte{
			[]byte("metadata"),
			token_metadata.ProgramID.Bytes(),
			mint.Bytes(),
			[]byte("edition"),
		},
		token_metadata.ProgramID,
	)
	return addr, err
}
