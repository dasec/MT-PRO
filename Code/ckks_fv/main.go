package ckks_fv

import (
	"crypto/rand"
	"fmt"
	"math"
	mrand "math/rand"
	"sort"

	//"github.com/ldsec/lattigo/v2/ckks"

	"github.com/ldsec/lattigo/v2/utils"
	"golang.org/x/crypto/sha3"
)


func Test() {
	testdatabase := true
	//add paths here 
	ptPath := ""
	encPath := ""
	contextPath := ""
	logPath := ""
	print(ptPath, encPath, contextPath, logPath)
	Test := NewDatabaseTest(encPath, ptPath, contextPath, logPath)
	Test.Init_Parties()
	Test.Run()

}
