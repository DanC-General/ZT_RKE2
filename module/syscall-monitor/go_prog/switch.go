package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type SeccompProfile struct {
	Architectures []string        `json:"architectures"`
	DefaultAction string          `json:"defaultAction"`
	Syscalls      []SyscallAction `json:"syscalls"`
}

type SyscallAction struct {
	Action string   `json:"action"`
	Names  []string `json:"names"`
}

// containerName : set (sys1, sys2)
var mappedSyscalls map[string]map[string]struct{}

func getSyscalls() string {
	complete := ""
	for cName, set := range mappedSyscalls {
		i := 0
		str := "\n    - list: " + cName + "-l\n      items: [ kill, prlimit, pselect6, setpgid, gettid, "
		// fmt.Println(cName + ":")
		for syscall := range set {
			// fmt.Print(syscall + ", ")
			str += syscall + ", "
			i++
			if i%5 == 0 {
				str += "\n            "
			}
		}
		str = str[:strings.LastIndex(str, ",")]
		str += " ]\n"
		complete += str
		// fmt.Println()
	}
	fmt.Println(complete)
	return complete
}
func writeRules() {
	f, err := os.OpenFile("../falco.yaml", os.O_APPEND|os.O_WRONLY, 0644)
	check(err)
	defer f.Close()
	for cName := range mappedSyscalls {
		rule :=

			"\n" + `    - rule: ` + cName + `-r 
      desc: notice abnormal syscall in ` + cName + `
      condition: > 
        syscall.type != null and
        not syscall.type in (` + cName + `-l) and evt.dir = >
        and container.id != host and 
        container.name = "` + cName + `" and 
        container.duration > 60000000000
      output: > 
        | ` + cName + ` | %container.image | %k8s.pod.name | %proc.pid
        |SYSCALLTYPE %syscall.type DONE| %container.duration | %evt.rawtime.s
        | %evt.rawtime.ns | %evt.rawtime
      priority: ALERT` + "\n\n"
		fmt.Println(rule)
		_, err = f.Write([]byte(rule))
		check(err)
	}
}
func recRead(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fmt.Println(file.Name(), file.IsDir())
		if file.IsDir() {
			recRead(dir + "/" + file.Name())
		} else {
			dir_split := strings.Split(dir, "sec_pols")
			if dir_split[1] == "" {
				continue
			}
			cName := dir_split[1][1:]
			_, exists := mappedSyscalls[cName]
			if !exists {
				mappedSyscalls[cName] = make(map[string]struct{})
			}
			fmt.Println(cName)
			f, err := os.Open(dir + "/" + file.Name())
			if err != nil {
				log.Println("Error opening file:", err)
				continue // Skip to next file if opening fails
			}
			defer f.Close() // Ensure file is closed even in case of errors

			// Read the entire file content into a byte slice
			byteValue, err := io.ReadAll(f)
			if err != nil {
				// log.Println("Error reading file:", err)
				continue // Skip to next file if reading fails
			}

			// Unmarshal the JSON content
			var result SeccompProfile
			err = json.Unmarshal(byteValue, &result)
			if err != nil {
				// log.Println("Error unmarshaling JSON:", err)
				continue // Skip to next file if unmarshalling fails
			}
			for i := range result.Syscalls[0].Names {
				// fmt.Println(result.Syscalls[0].Names[i])
				mappedSyscalls[cName][result.Syscalls[0].Names[i]] = struct{}{}
			}
			// fmt.Println(result.Syscalls[0].Names)
			// mappedSyscalls[]
			// if d, ok := result["syscalls"].(SysDat); ok {
			// 	fmt.Println(d.Names)
			// }
		}
	}
}
func main() {
	mappedSyscalls = make(map[string]map[string]struct{})
	recRead("../../policy/sec_pols")
	fmt.Println(mappedSyscalls)
	err := exec.Command("cp", "../base.yaml", "../falco.yaml").Run()
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile("../falco.yaml", os.O_APPEND|os.O_WRONLY, 0644)
	check(err)
	defer f.Close()
	_, err = f.Write([]byte(getSyscalls()))
	check(err)
	writeRules()
}
