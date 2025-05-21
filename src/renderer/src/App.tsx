import Versions from './components/Versions'
import BearCut from './assets/bear-cut.svg'
function App(): React.JSX.Element {
  const ipcHandle = (): void => window.electron.ipcRenderer.send('ping')

  return (
    <div className="flex h-[100svh] w-full flex-col bg-white/50">
      <div
        className="flex h-15 items-center px-20"
        style={{
          // @ts-expect-error Electron API
          appRegion: 'drag'
        }}
      >
        <h1 className="font-bold">BearWarden</h1>
      </div>
      <div className="grid h-full w-full grid-cols-[200px_1fr]">
        <div className="flex h-full flex-col gap-2 p-2 pt-0"></div>
        <div className="relative p-2 pt-0">
          <div className="relative flex h-full flex-col gap-2 rounded-lg bg-white/90 shadow-lg">
            <img
              src={BearCut}
              alt="BearWarden"
              className="absolute inset-0 m-auto size-[70vmin] opacity-50 select-none"
            />
            <h1 className="text-3xl font-bold underline">Hello world!</h1>
            <button onClick={ipcHandle}>Click me</button>
            <Versions></Versions>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
