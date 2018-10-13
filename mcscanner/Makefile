mcscanner: main.cpp mcWindow.cpp mcSniff.cpp
	g++ main.cpp mcWindow.cpp mcSniff.cpp -o mcscanner `pkg-config gtkmm-3.0 --cflags --libs` -lpcap -lrt

clean:
	rm -f mcscanner