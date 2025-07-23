// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"

	"golang.org/x/example/hello/reverse"
)

func main() {
	s := reverse.String("Hello")
	i := reverse.Int(24601)
	//i2 := reverse.IntBackdoor(24601)
	//fmt.Println("reverse int2", i2)

	fmt.Println("reverse string", s)
	fmt.Println("reverse int", i)
}
