//! 双向数据转发。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xxxr_common::Result;
use xxxr_net::Conn;

/// 缓冲区大小。
const BUFFER_SIZE: usize = 16 * 1024;

/// 一次可读事件。
enum Event {
    /// 左连接可读，附带读取字节数。
    Left(usize),
    /// 右连接可读，附带读取字节数。
    Right(usize),
}

/// 在两条连接之间双向转发数据，直到两端都关闭。
///
/// 任何一端读到 EOF 时会立刻对另一端执行 `shutdown`（半关闭语义），
/// 另一端仍有数据时继续转发。
pub async fn pump(left: &mut dyn Conn, right: &mut dyn Conn) -> Result<()> {
    let mut left_open = true;
    let mut right_open = true;
    let mut left_buf = vec![0u8; BUFFER_SIZE];
    let mut right_buf = vec![0u8; BUFFER_SIZE];

    while left_open || right_open {
        // 读写事件在独立作用域内产生，确保 select 的 future 在写回之前释放。
        let event = {
            tokio::select! {
                result = left.read(&mut left_buf), if left_open => Event::Left(result?),
                result = right.read(&mut right_buf), if right_open => Event::Right(result?),
            }
        };
        match event {
            Event::Left(0) => {
                left_open = false;
                right.shutdown().await?;
            }
            Event::Left(read) => {
                right.write_all(&left_buf[..read]).await?;
                right.flush().await?;
            }
            Event::Right(0) => {
                right_open = false;
                left.shutdown().await?;
            }
            Event::Right(read) => {
                left.write_all(&right_buf[..read]).await?;
                left.flush().await?;
            }
        }
    }
    Ok(())
}
