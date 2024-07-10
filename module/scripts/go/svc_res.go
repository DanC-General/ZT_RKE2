package main

import (
	"context"
	"fmt"

	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	mv1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	config, err := clientcmd.BuildConfigFromFlags("", "config.yaml")
	check(err)
	cs, err := clientset.NewForConfig(config)
	check(err)
	// fmt.Println(cs.ProjectcalicoV3().HostEndpoints().List(context.Background(), mv1.ListOptions{})
	// cur_cali, err := cs.ProjectcalicoV3().GlobalNetworkPolicies().List(context.Background(), mv1.ListOptions{})
	cur_cali, err := cs.ProjectcalicoV3().Profiles().List(context.Background(), mv1.ListOptions{})
	check(err)
	for _, svc := range cur_cali.Items {
		fmt.Println("Calico is ", svc)
	}

	// clientset, err := kubernetes.NewForConfig(config)
	// check(err)
	// calics, err := calcli.NewForConfig(config)
	// check(err)
	// cur_svcs, err := clientset.CoreV1().Services("default").List(context.Background(), mv1.ListOptions{})
	// check(err)
	// for _, svc := range cur_svcs.Items {
	// 	fmt.Println("Service is ", svc)
	// }
	// cur_pods, err := clientset.CoreV1().Pods("default").List(context.Background(), mv1.ListOptions{})
	// check(err)
	// for _, svc := range cur_pods.Items {
	// 	fmt.Println("Pod is ", svc)
	// }
	// cur_eps, err := clientset.CoreV1().Endpoints("default").List(context.Background(), mv1.ListOptions{})
	// check(err)
	// for _, svc := range cur_eps.Items {
	// 	fmt.Println("Endpoint is ", svc)
	// }
}
