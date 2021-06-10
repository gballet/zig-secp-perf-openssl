const std = @import("std");
const openssl = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/obj_mac.h");
    @cInclude("openssl/ec.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/evp.h");
});
const crypto = std.crypto;

pub fn main() anyerror!void {
    var err = openssl.OPENSSL_init_crypto(openssl.OPENSSL_INIT_LOAD_CONFIG, null);
    defer openssl.OPENSSL_cleanup();

    var grp: ?*openssl.EC_GROUP = openssl.EC_GROUP_new_by_curve_name(openssl.NID_secp256k1);
    if (grp == null) {
        return error.CouldNotGetGroup;
    }
    defer openssl.EC_GROUP_free(grp);

    var p: ?*openssl.EC_POINT = openssl.EC_POINT_new(grp);
    if (p == null) {
        return error.CouldNotInitializePoint;
    }
    defer openssl.EC_POINT_free(p);

    var ctx = openssl.BN_CTX_new() orelse return error.CouldNotGetCtx;
    defer openssl.BN_CTX_free(ctx);

    var order: *openssl.BIGNUM = openssl.BN_new() orelse return error.CouldNotAllocateBigNum;
    if (openssl.EC_GROUP_get_order(grp, order, ctx) != 1) {
        return error.CouldNotGetOrder;
    }
    defer openssl.BN_free(order);

    var scalars: [1000]*openssl.BIGNUM = undefined;
    var i: usize = 0;
    while (i < scalars.len) : (i += 1) {
        scalars[i] = openssl.BN_new() orelse return error.CouldNotAllocateBigNum;
        defer openssl.BN_free(scalars[i]);
        if (openssl.BN_rand_range(scalars[i], order) != 1) {
            return error.CouldNotGetRandomBigNum;
        }
    }

    var zero = openssl.BN_new() orelse return error.CouldNotAllocateBigNum;
    if (openssl.BN_zero(zero) != 1) {
        return error.CouldNotSetZero;
    }
    defer openssl.BN_free(zero);
    var r = openssl.EC_POINT_new(grp) orelse return error.CouldNotAllocateBigNum;
    defer openssl.EC_POINT_free(r);
    var dummy = openssl.EC_POINT_new(grp);
    defer openssl.EC_POINT_free(dummy);

    var f = try std.fs.cwd().createFile("zig.csv", std.fs.File.CreateFlags{});
    defer f.close();

    var count: usize = 0;
    while (count < 1000) : (count += 1) {
        std.log.info("entry {}", .{count});
        const start = std.time.nanoTimestamp();
        for (scalars) |scalar| {
            if (openssl.EC_POINT_mul(grp, r, scalar, r, zero, ctx) != 1) {
                return error.CouldNotMultiply;
            }
        }
        const end = std.time.nanoTimestamp();

        try f.writer().print("{},{}\n", .{ count, @divTrunc(end - start, 1000) });
    }
}
