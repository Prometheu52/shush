const std = @import("std");
const native_endian = @import("builtin").cpu.arch.endian();

const k_consts: [64]u32 = [_]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
const h_init: [8]u32 = [_]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 
};
const SHA256_core = struct {
    w_block: [64]u32 = undefined,
    state: [8]u32 = h_init,
    message_len: u64 = 0,

    fn choice(x: u32, y: u32, z: u32) u32 {
        return (x & y) ^ (~x & z);
    }

    fn majority(x: u32, y: u32, z: u32) u32 {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    fn sum_zero(x: u32) u32 {
        return std.math.rotr(u32, x, 2) ^ std.math.rotr(u32, x, 13) ^ std.math.rotr(u32, x, 22); 
    }

    fn sum_one(x: u32) u32 {
        return std.math.rotr(u32, x, 6) ^ std.math.rotr(u32, x, 11) ^ std.math.rotr(u32, x, 25); 
    }

    fn sig_zero(x: u32) u32 {
        return std.math.rotr(u32, x, 7) ^ std.math.rotr(u32, x, 18) ^ x >> 3; 
    }

    fn sig_one(x: u32) u32 {
        return std.math.rotr(u32, x, 17) ^ std.math.rotr(u32, x, 19) ^ x >> 10; 
    }

    fn digest_block(self: *SHA256_core, m_block: [64]u8) void {
        for (0..16) |i| {
            const val = std.mem.bytesToValue(u32, m_block[i*4..i*4+4]);
            self.w_block[i] = if (native_endian == .little) @byteSwap(val) else val;
        }

        for (16..self.w_block.len) |i| {
            const val = SHA256_core.sig_one(self.w_block[i-2]) 
                +% self.w_block[i-7] 
                +% SHA256_core.sig_zero(self.w_block[i-15]) 
                +% self.w_block[i-16];
            self.w_block[i] = val;
        }

        var block_state = self.state;
        for (0..64) |i| {
            const tmp1 = block_state[7] 
                +% SHA256_core.sum_one(block_state[4]) 
                +% SHA256_core.choice(block_state[4],block_state[5], block_state[6])
                +% k_consts[i]
                +% self.w_block[i];

            const tmp2 = SHA256_core.sum_zero(block_state[0]) 
                +% SHA256_core.majority(block_state[0], block_state[1], block_state[2]);

            block_state[7] = block_state[6];
            block_state[6] = block_state[5];
            block_state[5] = block_state[4];
            block_state[4] = block_state[3] +% tmp1;
            block_state[3] = block_state[2];
            block_state[2] = block_state[1];
            block_state[1] = block_state[0];
            block_state[0] = tmp1 +% tmp2;
        }

        for (0..self.state.len) |i| {
            self.state[i] +%= block_state[i];
        }

    }

    fn getHashString(self: SHA256_core, allocator: std.mem.Allocator) []const u8 {
        const str = std.fmt.allocPrint(allocator, "{X:0>4}{X:0>4}{X:0>4}{X:0>4}{X:0>4}{X:0>4}{X:0>4}{X:0>4}", .{self.state[0], self.state[1], self.state[2], self.state[3], self.state[4], self.state[5], self.state[6], self.state[7]}) catch "FMT FAILED";
        return str;
    }
    
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const result_str_allocator = std.heap.page_allocator;
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Discard the first argument
    _ = args.skip();
    const file_path = args.next() orelse "C:\\Users\\mgfea\\Dev\\Zig\\shush\\input.txt";

    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        std.debug.print("Error: {any}", .{err});
        return;
    };
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var big_boi_buff = [_]u8{0} ** (64 * 16);
    var message_block = [_]u8{0} ** 64;
    message_block[0] = 0x80;

    var sha256 = SHA256_core{};

    var is_first_run = true;
    while(true):(is_first_run = false) {
        const bytes_read = try in_stream.read(&big_boi_buff);
        if (bytes_read == 0) {
            if (is_first_run) {
                sha256.digest_block(message_block);
            }
            break;
        }

        sha256.message_len += bytes_read;

        std.debug.assert(big_boi_buff.len % 64 == 0);
        const chunks = big_boi_buff.len / 64;

        for (0..chunks) |processed_chunks| {
            const start = processed_chunks * 64;
            const end = if (start + 64 > bytes_read) bytes_read else start + 64;

            for (big_boi_buff[start..end], 0..) |item, i| {
                message_block[i] = item;
            }

            if (end % 64 < 56) {
                message_block[end % 64] = 0x80;
                const size = std.mem.nativeToBig(u64, sha256.message_len * 8);
                for (std.mem.asBytes(&size), 56..) |byte, i| {
                    message_block[i] = byte;
                }
            } else if (end % 64 > 56 and end % 64 != 0) {
                message_block[end % 64] = 0x80;
                sha256.digest_block(message_block);

                message_block = [_]u8{0} ** 64;
                const size = std.mem.nativeToBig(u64, sha256.message_len * 8);
                for (std.mem.asBytes(&size), 56..) |byte, i| {
                    message_block[i] = byte;
                }
            }

            sha256.digest_block(message_block);

            if (bytes_read == end) break;
            
        }
    }

    std.debug.print("{s}", .{sha256.getHashString(result_str_allocator)});
   
}

fn pretty_print_buf(buf: []u8, col_num: u32) void {
    for (buf, 1..) |byte, i| {
        if (i % col_num == 0) {
            std.debug.print("{s:>2}{X:<3} \n\n", .{"0x", byte});
            continue;
        }
        std.debug.print("{s:>2}{X:<3} ", .{"0x", byte});
    }
}
