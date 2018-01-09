// Copyright (c) 2017 Pani Networks
// All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Command for adjusting the source-dest-check attribute on EC2 instances
// when running Romana on a Kubernetes cluster.
package main

import (
	// stdlib imports
	"log"
	"os"
	"os/signal"
	"time"

	// aws-sdk-go imports
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	// k8s client-go imports
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"golang.org/x/sys/unix"
)

func main() {
	// aws api client
	awsSession, err := session.NewSession()
	if err != nil {
		log.Printf("error initializing global session: %s", err)
		return
	}

	// kubernetes api client
	cc, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("error in creating in-cluster config: %s", err)
		return
	}
	client, err := kubernetes.NewForConfig(cc)
	if err != nil {
		log.Printf("error in creating in-cluster client: %s", err)
		return
	}

	// node informer using kubernetes api client
	store, controller := cache.NewInformer(
		cache.NewListWatchFromClient(
			client.Core().RESTClient(),
			"nodes",
			v1.NamespaceAll,
			fields.Everything()),
		&v1.Node{},
		1*time.Minute,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				add(awsSession, obj)
			},
			DeleteFunc: del,
			UpdateFunc: upd,
		},
	)

	// store is not used
	_ = store

	// start the controller
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		controller.Run(stopCh)
		close(doneCh)
	}()

	// run until killed or interrupted
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, unix.SIGTERM)
	select {
	case <-sigCh:
		close(stopCh)
	case <-doneCh:
		close(stopCh)
	}
}

func add(awsSession *session.Session, obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		log.Printf("expected *v1.Node, got %T", obj)
		return
	}
	// Expect external id, region and zone
	// zone is not required, but still expected.
	externalID := node.Spec.ExternalID
	if externalID == "" {
		log.Println("no value for node.Spec.ExternalID on node", node.ObjectMeta.Name)
		return
	}
	region, ok := node.ObjectMeta.Labels[unversioned.LabelZoneRegion]
	if !ok {
		log.Println("no value for label", unversioned.LabelZoneRegion, "on node", node.ObjectMeta.Name)
		return
	}
	if region == "" {
		log.Println("empty value for label", unversioned.LabelZoneRegion, "on node", node.ObjectMeta.Name)
		return
	}
	zone, ok := node.ObjectMeta.Labels[unversioned.LabelZoneFailureDomain]
	if !ok {
		log.Println("no value for label", unversioned.LabelZoneFailureDomain, "on node", node.ObjectMeta.Name)
		return
	}
	if zone == "" {
		log.Println("empty value for label", unversioned.LabelZoneFailureDomain, "on node", node.ObjectMeta.Name)
		return
	}

	// Try to modify the EC2 Instance attribute
	ec2Client := ec2.New(awsSession, aws.NewConfig().WithRegion(region))
	ec2Req := &ec2.ModifyInstanceAttributeInput{
		InstanceId:      aws.String(externalID),
		SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
	}
	_, err := ec2Client.ModifyInstanceAttribute(ec2Req)
	if err != nil {
		log.Printf("error updating EC2 instance attribute 'SourceDestCheck' for instance %s (node %s)", externalID, node.ObjectMeta.Name)
		return
	}
	log.Printf("successfully updated EC2 instance attribute 'SourceDestCheck' for instance %s (node %s)", externalID, node.ObjectMeta.Name)

}

func del(obj interface{}) {
}

func upd(oldObj, newObj interface{}) {
}
