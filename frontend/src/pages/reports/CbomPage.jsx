import CBOMViewer from '../../components/CBOMViewer';
import { useAppData } from '../../context/AppDataContext.jsx';

const CbomPage = () => {
  const { assets } = useAppData();
  return <CBOMViewer assets={assets} />;
};

export default CbomPage;
