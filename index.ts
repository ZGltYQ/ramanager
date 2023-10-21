const addon = require('./build/Release/addon');

class RAManager {
    procName: string;
    pid: number;

    constructor(processName: string) {
        this.procName = processName;
        this.pid = addon.getProcessPid(processName);
    }

    getProcessPid(): number {
        return this.pid;
    }

    getProcessAddresses(): number[] {
        return addon.getProcessAddresses(this.pid)
    }

    readMemory(address: number): any {
        return addon.readProcessMemory(this.pid, address);
    }

    writeMemory(address: number, value: any): void {
        return addon.writeProcessMemory(this.pid, address, value);
    }

    findAddressesByValue(value: any): object {
        const result : any = {};

        for (const address of this.getProcessAddresses()) {
            if (this.readMemory(address) === value) result[address] = value;
        }

        return result;
    }
}

const test = new RAManager('chrome');

console.log(test.getProcessAddresses())

console.log(test.readMemory(0x06488534))