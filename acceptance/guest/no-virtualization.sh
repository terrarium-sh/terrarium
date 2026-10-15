# The guest gets no hardware virtualization: no VMX/SVM on x86, no EL2 on ARM.
case "$(uname -m)" in
  x86_64) ! grep -qw -e vmx -e svm /proc/cpuinfo ;;
  aarch64) dmesg | grep -q 'CPU: All CPU(s) started at EL1' ;;
  *) exit 1 ;;
esac
