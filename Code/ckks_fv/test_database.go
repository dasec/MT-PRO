package ckks_fv

import (
	"fmt"
	"log"
	"os"
	"time"
)

type DTesting interface {
	Init_Parties()
	Run()
}

type d_testing struct {
	EncryptedTemplateDir string
	PlainTemplateDir     string
	shared               Shared
	client               Client
	serverAuth           ServerAuth
	serverComp           ServerComp
	contextPath          string
	subjectMap           map[string][]MultiTemplate
}

func openLogFile(path string) (*os.File, error) {
	logFile, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return logFile, err
}

func NewDatabaseTest(encryptedTemplateDir string, plainTemplateDir string, contextPath string, logPath string) DTesting {
	test := new(d_testing)
	pte, etc := !FileOrFolderExists(plainTemplateDir), !FileOrFolderExists(encryptedTemplateDir)
	if pte && etc {
		panic("Neither encrypted template folder or plain text folder exists")
	}
	if etc {
		fmt.Println("Encrypted Template Dir does not exist and will be created if necessary")
	} else {
		test.EncryptedTemplateDir = encryptedTemplateDir
	}
	if pte {
		fmt.Println("Plain Template Dir does not exist")
	} else {
		test.PlainTemplateDir = plainTemplateDir
	}
	test.contextPath = contextPath
	file, err := openLogFile(logPath)
	if err == nil {
		log.SetOutput(file)
		log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	}
	test.subjectMap = make(map[string][]MultiTemplate)
	return test
}
func (test *d_testing) Init_Parties() {
	if !FileOrFolderExists(test.contextPath) {
		test.Init_Parties_Fresh(4, 0, 2)
	} else {
		test.Init_Parties_from_File()
	}

}
func (test *d_testing) Init_Parties_Fresh(numRound int, paramIndex int, radix int) {
	fmt.Println("Init Parties and save to file: ")
	fmt.Println("\nInit shared With Params")
	test.shared = Init(numRound, paramIndex, radix, true)
	fmt.Println("\nInit Authentication Server")
	test.serverAuth = NewServerAuth(test.shared)
	fmt.Println("\nInit Computation Server")
	test.serverComp = NewServerComp(test.shared)
	fmt.Println("\nInit Client")
	test.client = NewClient(test.shared)
	Print_context(test.shared)
	SaveContext(test.contextPath, test.shared, test.serverAuth)

}
func (test *d_testing) Init_Parties_from_File() {
	context := DeserializeContextFC(test.contextPath)
	context.PrintContext()
	numRound, paramIndex, radix, fullCoeffs, nonces := context.GetSharedParameters()
	fmt.Println("\nInit shared")
	test.shared = Init(numRound, paramIndex, radix, fullCoeffs)

	test.shared.SetNonces(nonces)
	fmt.Println("\nInit Authentication Server")
	test.serverAuth = NewServerAuthFromContextFC(test.shared, context)
	fmt.Println("\nInit Computation Server")
	test.serverComp = NewServerComp(test.shared)
	fmt.Println("\nInit Client")
	test.client = NewClient(test.shared)
	Print_context(test.shared)
}
func (test *d_testing) GetInstructions() []*TemplateInstruction {

	irisInstruction := NewIrisValentinaTemplateInstruction(0)
	fingerInstruction := NewFingerValentinaTemplateInstruction(irisInstruction.TemplateLength)
	instructions := []*TemplateInstruction{irisInstruction, fingerInstruction}
	return instructions
}
func (test *d_testing) TranscipherMap() {
	for k, v := range test.subjectMap {
		AddSubjectFolder(test.EncryptedTemplateDir, k)
		for i, m := range v {
			t := ProbePath(test.EncryptedTemplateDir, k, m.GetName())
			if FileOrFolderExists(t) {
				continue
			}

			sym_key := test.client.GenerateRandomKey()
			sym_ct, he_key := test.client.EncryptMultipleTemplates(m.GetTemplates(), sym_key, 1, test.shared.GetMessagesSize())
			transciphered, sym_time, he_time := test.serverComp.TranscipherFirstMessageTimings(sym_ct, he_key)
			log.Printf("%v; %v;  %v", m.GetName(), sym_time, he_time)
			sct := NewSingleCiphertextSerialized("0", transciphered)
			SerializeCiphertext(sct, t)
			log.Printf("%v - saved: %v", m.GetName(), i)

		}
	}
}
func (test *d_testing) MapTemplates(start int) {
	allSubjectIds := GetAllSubjectIDsFromFolder(test.PlainTemplateDir)
	instructions := test.GetInstructions()
	for i := start; i < len(allSubjectIds); i++ {

		//for i := start; i < len(allSubjectIds); i++ {
		//println(allSubjectIds[i])
		subFolder := GetAllFileFromSubFolder(test.PlainTemplateDir, allSubjectIds[i])
		irisTemplates := GetAllFileFromFolder(subFolder[0])
		fingerTemplates := GetAllFileFromFolder(subFolder[1])
		multiTemplates := make([]MultiTemplate, 0)
		for j, iris := range irisTemplates {
			irisT := NewTemplate(iris)
			fingerT := NewTemplate(fingerTemplates[j], true)
			templates := []Template{irisT, fingerT}
			combined := NewMultiTemplate(templates, instructions, allSubjectIds[i])
			multiTemplates = append(multiTemplates, combined)
		}
		test.subjectMap[allSubjectIds[i]] = multiTemplates
	}
	print("Mapped")
}
func (test *d_testing) ReadCiphertexts() {
	allSubjectIds := GetAllSubjectIDsFromFolder(test.EncryptedTemplateDir)
	instructions := test.GetInstructions()
	for i := 0; i < 3; i++ {
		//for i := start; i < len(allSubjectIds); i++ {
		//println(allSubjectIds[i])
		probe := GetAllFileFromSubFolder(test.EncryptedTemplateDir, allSubjectIds[i])
		fmt.Println("Read probe: ", probe[0])
		temp0cs := DeserializeCiphertext(probe[0])
		temp0 := temp0cs.ConvertToRegularCiphertext()[0]
		temp1cs := DeserializeCiphertext(probe[1])
		temp1 := temp1cs.ConvertToRegularCiphertext()[0]
		dist := test.serverComp.ProcessTemplateInstructionsSingleCT(instructions, temp0, temp1)
		dec := test.serverAuth.DecryptMessage(dist)
		fmt.Println("Distance: ", real(dec[0]))
	}
}

func (test *d_testing) SetCiphertexts(subjectId string) {
	multiTemplates := test.subjectMap[subjectId]
	for _, m := range multiTemplates {
		encPath := ProbePath(test.EncryptedTemplateDir, subjectId, m.GetName())
		if !FileOrFolderExists(encPath) {

			continue
		}
		temp0cs := DeserializeCiphertext(encPath)
		temp0 := temp0cs.ConvertToRegularCiphertext()[0]
		m.SetCiphertext(temp0)
	}
}

func (test *d_testing) SetCiphertext(subject MultiTemplate) {
	encPath := ProbePath(test.EncryptedTemplateDir, subject.GetSubjectID(), subject.GetName())
	if !FileOrFolderExists(encPath) {
		return
	}
	temp0cs := DeserializeCiphertext(encPath)
	temp0 := temp0cs.ConvertToRegularCiphertext()[0]
	subject.SetCiphertext(temp0)
}

func (test *d_testing) MatedComparisonOneSubject(subjectId string) {
	multiTemplates := test.subjectMap[subjectId]
	mated_path := MatedPath(test.EncryptedTemplateDir, subjectId)
	if FileOrFolderExists(mated_path) {
		fmt.Println("File already exists:", mated_path)
		return
	}
	test.SetCiphertexts(subjectId)
	instructions := test.GetInstructions()
	results_ct := make([]float64, 0)
	results_pt := make([]float64, 0)
	for i, _ := range multiTemplates {
		probe := multiTemplates[i]
		probe_ct, err := probe.GetCiphertext()
		if err != nil {
			log.Println("Missing encrypted file for", probe.GetName())
			continue
		}
		for j := i + 1; j < len(multiTemplates); j++ {
			reference := multiTemplates[j]
			ref_ct, err := reference.GetCiphertext()
			if err != nil {
				log.Println("Missing encrypted file for", probe.GetName())
				continue
			}
			start := time.Now()
			distance_ct := test.serverComp.ProcessTemplateInstructionsSingleCT(instructions, ref_ct, probe_ct)
			compute_time := time.Since(start).Seconds()
			start = time.Now()
			dec := test.serverAuth.DecryptMessage(distance_ct)
			//Print_decrypted_message(dec)
			distance_pt := real(dec[0]) + (real(dec[instructions[1].Index]) * 2)
			//println("[0]:", real(dec[0]), "[", instructions[1].Index, "]:", real(dec[instructions[1].Index])*2, " sum:", distance_pt)
			decrypt_time := time.Since(start).Seconds()
			distance_clear := probe.Distance(reference)
			//println("clear ", distance_clear)
			results_ct = append(results_ct, distance_pt)
			results_pt = append(results_pt, distance_clear)
			log.Printf("mated: %v - %v; %v; %v; %v, %v", probe.GetName(), reference.GetName(), distance_pt, distance_clear, compute_time, decrypt_time)
		}
	}
	WriteResultsToFile(mated_path, results_ct, results_pt)
}

func (test *d_testing) NonMatedComparisonOneSubject(probe MultiTemplate, others []MultiTemplate) {
	subjectId := probe.GetSubjectID()
	nonmated_path := NonMatedPath(test.EncryptedTemplateDir, subjectId)
	if FileOrFolderExists(nonmated_path) {
		fmt.Println("File already exists:", nonmated_path)
		return
	}
	//test.SetCiphertexts(subjectId)
	instructions := test.GetInstructions()
	results_ct := make([]float64, 0)
	results_pt := make([]float64, 0)

	probe_ct, err := probe.GetCiphertext()
	if err != nil {
		log.Println("Missing encrypted file for", probe.GetName())
		return
	}
	for j := 0; j < len(others); j++ {
		reference := others[j]
		ref_ct, err := reference.GetCiphertext()
		if err != nil {
			log.Println("Missing encrypted file for", probe.GetName())
			continue
		}
		start := time.Now()
		distance_ct := test.serverComp.ProcessTemplateInstructionsSingleCT(instructions, ref_ct, probe_ct)
		compute_time := time.Since(start).Seconds()
		start = time.Now()
		dec := test.serverAuth.DecryptMessage(distance_ct)
		//Print_decrypted_message(dec)
		distance_pt := real(dec[0]) + (real(dec[instructions[1].Index]) * 2)
		//println("[0]:", real(dec[0]), "[", instructions[1].Index, "]:", real(dec[instructions[1].Index])*2, " sum:", distance_pt)
		decrypt_time := time.Since(start).Seconds()
		distance_clear := probe.Distance(reference)
		//println("clear ", distance_clear)
		results_ct = append(results_ct, distance_pt)
		results_pt = append(results_pt, distance_clear)
		log.Printf("mated: %v - %v; %v; %v; %v, %v", probe.GetName(), reference.GetName(), distance_pt, distance_clear, compute_time, decrypt_time)
	}

	WriteResultsToFile(nonmated_path, results_ct, results_pt)
}
func (test *d_testing) writeTimingLog(iterations int) {
	it := 0
	for k, v := range test.subjectMap {
		AddSubjectFolder(test.EncryptedTemplateDir, k)
		for _, m := range v {
			if it == iterations {
				break
			}
			sym_key := test.client.GenerateRandomKey()
			sym_ct, he_key, s_t, h_t := test.client.EncryptMultipleTemplatesTiming(m.GetTemplates(), sym_key, 1, test.shared.GetMessagesSize())
			_, sym_time, he_time := test.serverComp.TranscipherFirstMessageTimings(sym_ct, he_key)
			trans_t := sym_time + he_time
			start := time.Now()
			test.serverComp.EncryptProbeDirectlySingleCiphertext(ConnectTemplates(m.GetTemplates()))
			direct := time.Since(start).Seconds()
			log.Printf("%v; %v;  %v; %v", s_t, h_t, trans_t, direct)
			it++
		}
	}
}

func (test *d_testing) Run() {
	test.Init_Parties()
	test.MapTemplates(0)
	mated := false
	nonMated := true
	if mated {
		for k, _ := range test.subjectMap {
			test.MatedComparisonOneSubject(k)
		}
	}
	if nonMated {
		firsts := make([]MultiTemplate, 0)
		for k, _ := range test.subjectMap {
			template := test.subjectMap[k]
			nonmated_path := NonMatedPath(test.EncryptedTemplateDir, k)

			if FileOrFolderExists(nonmated_path) {
				fmt.Println("File already exists:", nonmated_path)
				continue
			}
			test.SetCiphertext(template[0])
			firsts = append(firsts, template[0])
			//test.MatedComparisonOneSubject(k)
		}
		for i, template := range firsts {
			fmt.Println("At index ", i, " /", len(firsts))
			test.NonMatedComparisonOneSubject(template, firsts)
			//remove current element
			copy(firsts[i:], firsts[i+1:])
			firsts = firsts[:len(firsts)-1]
		}
	}

}
