// 生成精确 origin + VID/PID 的 Edge 官方策略值；不修改用户机器全局策略。
const vid = Number(process.env.VLP_USB_VID ?? "0x10c4"),
  pid = Number(process.env.VLP_USB_PID ?? "0xea60");
for (const n of [vid, pid])
  if (!Number.isInteger(n) || n < 0 || n > 65535)
    throw Error("VID/PID 必须为 0..65535 整数。");
console.log(
  JSON.stringify(
    {
      SerialAllowUsbDevicesForUrls: [
        {
          devices: [{ vendor_id: vid, product_id: pid }],
          urls: ["http://127.0.0.1:4173"],
        },
      ],
    },
    null,
    2,
  ),
);
