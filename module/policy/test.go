package main

// Import necessary libraries
import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	cv1 "k8s.io/api/core/v1"

	// "k8s.io/client-go/rest"
	mv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	// "k8s.io/client-go/tools/watch"
)

// { container_name [ container_id1 : pid1, container_id2 : pid2 ]}
var pid_stores map[string]map[string]string
var DIR string = "./sec_pols/"
var n_to_gad map[string]string

func main() {
	capture_syscalls()
}
func capture_syscalls() {
	if n_to_gad == nil {
		n_to_gad = make(map[string]string)
	}
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		// Handle error
		fmt.Println("Error :(")
	}
	timeOut := int64(60)
	watchInterface, _ := clientset.CoreV1().Pods("default").Watch(context.Background(), mv1.ListOptions{TimeoutSeconds: &timeOut})

	// Handle watch events in a loop
	for event := range watchInterface.ResultChan() {
		fmt.Println(event.Type)
		if event.Type == "MODIFIED" {
			podName := handlePod(event.Object.(*cv1.Pod))
			if podName == "" {
				continue
			}
			n_to_gad[podName] = start_capture(podName)
		} else if event.Type == "ADDED" {
			// Start a gadget seccomp capture
			podName := handlePod(event.Object.(*cv1.Pod))
			if podName == "" {
				continue
			}
			n_to_gad[podName] = start_capture(podName)
		} else if event.Type == "DELETED" {
			podName := handlePod(event.Object.(*cv1.Pod))
			if podName == "" {
				continue
			}
			fmt.Println("delete finished")
			end_capture(podName, n_to_gad[podName])
		}
		fmt.Println(n_to_gad)
	}
	for name, id := range n_to_gad {
		end_capture(name, id)
	}
}

func handlePod(pod *cv1.Pod) string {
	fmt.Println(pod)
	// fmt.Println(pod.Name, pod.Labels, pod.Annotations, "\nmeta\n", pod.ObjectMeta)
	cID := ""
	for k, v := range pod.Annotations {
		if strings.Contains(k, "containerID") {
			cID = v
		}
	}
	if cID == "" {
		for _, stat := range pod.Status.ContainerStatuses {
			cID = stat.ContainerID
		}
	}
	if cID == "" {
		fmt.Println("No CID. Returning...")
		return ""
	}
	pid := get_cid_pid(cID)
	fmt.Println(pod.Spec.Containers[0].Name, pod.Name, cID, pid)
	new_key := pod.Spec.Containers[0].Name
	if pid_stores == nil {
		pid_stores = make(map[string]map[string]string)
	}
	if pid_stores[new_key] == nil {
		pid_stores[new_key] = make(map[string]string)
	}
	_, exists := pid_stores[new_key][cID]
	if !exists {
		pid_stores[new_key][cID] = pod.Name
	}
	// fmt.Println(pod)
	// fmt.Println(pid_stores)
	// fmt.Println(n_to_gad)
	// return pod.Name
	return pod.Name
}

func get_cid_pid(cid string) string {

	cmd := "ps -ef | grep " + cid + " | tr -s [:space:]"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		panic(err)
	}
	pid := string(strings.Split(string(out), " ")[1])
	fmt.Println(pid)
	return pid
}

func start_capture(pName string) string {
	fmt.Println("Started capturing " + pName)
	cmd := "kubectl gadget advise seccomp-profile start -p " + pName
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + string(out))
		panic(err)
	}
	return string(out)
}
func end_capture(pName string, capID string) {
	// This is very inefficient and could easily rewrite to store map differently.
	var cName string
	for k, m := range pid_stores {
		// fmt.Println(k, m)
		for _, pod := range m {
			// fmt.Println(cid, pod)
			if pod == pName {
				cName = k
			}
		}
	}
	fmt.Println("Killing ", pName, " -> ", capID)
	fname := DIR + cName + "/" + pName + ".txt"
	if _, err := os.Stat(DIR + cName); os.IsNotExist(err) {
		// Create the directory with permissions 0755
		err = os.MkdirAll(DIR+cName, 0755)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}
		fmt.Println("Directory created successfully:", DIR+cName)
	}
	cmd := "kubectl gadget advise seccomp-profile stop " + capID
	// f, err := os.Create(fname)
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	out := exec.Command("bash", "-c", cmd)
	out.Stdout = f
	out.Run()
}
