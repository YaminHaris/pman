from tkinter import *
root = Tk(width=100, height=200)
w = Label(root, text='GeeksForGeeks.org!')
w.pack()
a = Button(root, text='helloworld',command=root.destroy)
a.pack()
root.mainloop()
