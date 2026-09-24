// Focused reproduction for the ipNetTable crash.
import 'package:netnatscan/services/win32_backend.dart' as b;

Future<void> main() async {
  for (var i = 0; i < 300; i++) {
    final rows = b.getArpTable();
    print('$i: ${rows.length} rows');
  }
  print('DONE');
}
