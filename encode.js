// encode.js
const crypto = require('./original.js');

const [_, __, funcName, ...args] = process.argv;

try {
    // 动态获取函数
    const targetFunc = crypto[funcName];
    if (typeof targetFunc !== 'function') {
        throw new Error(`函数 ${funcName} 不存在`);
    }

    // 解析参数（支持JSON字符串或原始字符串）
    const parsedArgs = args.map(arg => {
        try {
            return JSON.parse(arg);
        } catch {
            return arg; // 保留非JSON字符串
        }
    });

    // 执行并输出结果
    const result = targetFunc(...parsedArgs);
    console.log(JSON.stringify(result));

} catch (err) {
    console.error(err.message);
    process.exit(1);
}