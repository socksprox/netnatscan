import 'package:flutter_test/flutter_test.dart';

import 'package:netnatscan/main.dart';

void main() {
  testWidgets('App renders scan screen', (WidgetTester tester) async {
    await tester.pumpWidget(const NetNatScanApp());
    expect(find.text('Network Scan'), findsOneWidget);
  });
}
