# Resources

## Videos

- [BlackHat Asia 2017 - Evasive Hollow Process Injection](https://www.youtube.com/watch?v=9L9I1T5QDg4)
  - On execution, process loads Process Environment Block (PEB), Dynamic Linked Libs (DLLs), and the executable 
    - PEB contains metadata (memory address start, full path, 3 double-linked lists)
    - LoadOrderList, MemoryOrderList, InitOrderList link to modules (DLLs)
      - Easy to enumerate modules loaded in user memory by walking these lists
        - This is how Volatility plug-ins such as `dlllist` work.
        - the proper way to check (to catch unlinked modules) is compare the libraries from the PEB double-linked lists with the kernel's binary tree
      - **it's possible to unlink these modules**
      - The kernel sees this as a binary tree (VAD) with each node being the metadata for the module it represents
  - Steps for basic process hollowing:
    - Malware creates a legitimate process in the suspended state
    - Process executable section is deallocated (freed), reallocated, and replaced with a malicious executable
    - Thread is resumed, and the legitimate process begins executing the malware
  - the injected process will have `RWX` instead of `WCX` protections, a possible tip for 4n6 tools
  - the Taidoor malware employed good evasion techniques 
    - allocated a new memory block, then re-pointed the PEB to that allocation of memory
    - the PID was a trigger, as well as the address discrepancy of svchost.exe (process has different base address for svchost.exe)
    - the malware confused forensicators by making the legitimate executable into a false positive, leading investigators down a rabbit hole.
    - `malfind` could still identify the malicious address between the two
    - using `strings` on the suspended process will also make it obvious, as there are not many strings in the suspended process
    - the VAD Protection (`WCX` vs `RWX`) is still a trigger
  - Kuluoz is another malware employing evasion
    - patched the legitimate `svchost.exe` and pointed it to an allocated block of malicious code
      - the patch was just `nop`,`push <0xdeadbeef>`,`ret`
    - still changed `WCX` to `RWX`, making it detectable via the changed VAD protection
    - again, the PID was bad (not `services.exe`)
    - Does not have a full path in the VAD node metadata or the PEB metadata
    - `malfind` does not identify the redirect, just the patch. HollowFind addresses this.
  - By modifying the parameter when allocating the new memory like Kuluoz did, you can create a `WCX` section for the injected code
    - this will cause the forensicator to try and analyze ONLY the patched process
    - HollowFind uses the logic "if it is not a PE but has `WCX`, it is probably malware because there is no need for non-exe to have `WCX` VAD protection. And it also must be loaded from the disk (no mapped file if malicious)"
    - Kronos uses this method
  - `explorer.exe` is good to use for process hollowing because of the parent process (user init) always terminating after start, so if you terminate your process it looks the same except for the timestamp

- 