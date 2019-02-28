package vote

import (
	"testing"
	"time"
	"fmt"
	"math/big"
	"github.com/usechain/go-usechain/common"
)

func TestNewVoter(t *testing.T) {
	var expire *time.Timer
	expire = time.NewTimer(time.Second*5)

	channel := <-expire.C
	fmt.Println("time is", channel)

	expire.Stop()
	expire.Reset(time.Second*5)

	channel = <-expire.C
	fmt.Println("time is", channel)


}
