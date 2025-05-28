package main

import (
	"context"
	"fmt"
	"time"
)

func main() {
	// 设置一个超时时间，比如 2 秒
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel() // 使用完毕后，确保调用 cancel 释放资源

	// 启动一个模拟的处理逻辑
	go func(ctx context.Context) {
		select {
		case <-time.After(2 * time.Second): // 模拟任务执行时间过长
			fmt.Println("任务完成")
		case <-ctx.Done(): // 超时或取消
			fmt.Println("任务取消，原因:", ctx.Err())
		}
	}(ctx)

	// 主线程等待
	time.Sleep(1 * time.Second) // 确保主线程不会过早退出
}
