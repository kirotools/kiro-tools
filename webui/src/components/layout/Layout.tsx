import { Outlet } from 'react-router-dom';
import Navbar from '../navbar/Navbar';
import BackgroundTaskRunner from '../common/BackgroundTaskRunner';
import ToastContainer from '../common/ToastContainer';
import { useViewStore } from '../../stores/useViewStore';
// MiniView is a Tauri-specific component, it should not be used in web mode
// import MiniView from './MiniView'; 

function Layout() {
    useViewStore();

    // In web mode, MiniView is not supported, so we always render the full layout
    // if (isMiniView) {
    //     return (
    //         <>
    //             <BackgroundTaskRunner />
    //             <ToastContainer />
    //             <MiniView />
    //         </>
    //     );
    // }

    return (
        <div className="h-screen flex flex-col bg-[#FAFBFC] dark:bg-base-300">
            <BackgroundTaskRunner />
            <ToastContainer />
            <Navbar />
            <main className="flex-1 overflow-hidden flex flex-col relative">
                <Outlet />
            </main>
        </div>
    );
}

export default Layout;
