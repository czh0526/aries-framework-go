package context

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSingleThread(t *testing.T) {
	t.Run("test task timeout", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelFunc()

		process(ctx)
	})

	t.Run("test task finish", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancelFunc()

		process(ctx)
	})
}

func process(ctx context.Context) {
	select {
	case <-time.After(3 * time.Second): // 模拟任务执行时间较长
		fmt.Println("任务执行完成")
	case <-ctx.Done(): // 检测超时或取消信号
		fmt.Println("任务失败，原因:", ctx.Err())
	}
}
