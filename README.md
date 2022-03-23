# cognito-token-verifier

Library for verifying ID tokens and getting user data from AWS Cognito User Pool.

# Usage:

1. Import library:

 ``````
import ctv "github.com/DrGermanius/cognitotokenverifier"
 ``````

2. Initialize verifier:

``````
v, err := ctv.InitVerifier(&ctv.Config{
		Region: "eu-central-1",
		PoolID: "eu-central-1_i1A111AAb",
	})
``````

3. Verify token:

``````
err = v.Verify(context.Background(), "YOUR_USER_POOL_ID_TOKEN")
``````

4. Get user attributes:

``````
attrs, err := v.GetUserAttributesByToken("YOUR_USER_POOL_ID_TOKEN")
``````

Full example:

``````
package main

import (
	"context"
	"fmt"
	"log"

	ctv "github.com/DrGermanius/cognitotokenverifier"
)

func main() {
        v, err := ctv.InitVerifier(&ctv.Config{
		Region: "eu-central-1",
		PoolID: "eu-central-1_i1A111AAb",
	})
	if err != nil {
		log.Fatalf("init verifier error: %s", err)
	}

	err = v.Verify(context.Background(), "YOUR_USER_POOL_ID_TOKEN")
	if err != nil {
		log.Fatalf("token verify error: %s", err)
	}

	attrs, err := v.GetUserAttributesByToken("YOUR_USER_POOL_ID_TOKEN")
	if err != nil {
		log.Fatalf("get user attributes error: %s", err)
	}

	fmt.Println(attrs)
}
``````
