'use client';

import React from 'react';
import {
  ArrowLeftIcon as OutlineArrowLeftIcon,
  ArrowUpTrayIcon as OutlineArrowUpTrayIcon,
  Bars3Icon as OutlineBars3Icon,
  BeakerIcon as OutlineBeakerIcon,
  BoltIcon as OutlineBoltIcon,
  ChartBarIcon as OutlineChartBarIcon,
  CheckCircleIcon as OutlineCheckCircleIcon,
  CommandLineIcon as OutlineCommandLineIcon,
  CpuChipIcon as OutlineCpuChipIcon,
  DocumentArrowDownIcon as OutlineDocumentArrowDownIcon,
  DocumentIcon as OutlineDocumentIcon,
  DocumentTextIcon as OutlineDocumentTextIcon,
  ExclamationCircleIcon as OutlineExclamationCircleIcon,
  ExclamationTriangleIcon as OutlineExclamationTriangleIcon,
  EyeIcon as OutlineEyeIcon,
  EyeSlashIcon as OutlineEyeSlashIcon,
  HomeIcon as OutlineHomeIcon,
  InformationCircleIcon as OutlineInformationCircleIcon,
  ListBulletIcon as OutlineListBulletIcon,
  LockClosedIcon as OutlineLockClosedIcon,
  LockOpenIcon as OutlineLockOpenIcon,
  MagnifyingGlassIcon as OutlineMagnifyingGlassIcon,
  QuestionMarkCircleIcon,
  RocketLaunchIcon as OutlineRocketLaunchIcon,
  ShieldCheckIcon as OutlineShieldCheckIcon,
  SparklesIcon as OutlineSparklesIcon,
  WrenchScrewdriverIcon as OutlineWrenchScrewdriverIcon,
  XMarkIcon as OutlineXMarkIcon,
} from '@heroicons/react/24/outline';
import {
  ArrowLeftIcon as SolidArrowLeftIcon,
  ArrowUpTrayIcon as SolidArrowUpTrayIcon,
  Bars3Icon as SolidBars3Icon,
  BeakerIcon as SolidBeakerIcon,
  BoltIcon as SolidBoltIcon,
  ChartBarIcon as SolidChartBarIcon,
  CheckCircleIcon as SolidCheckCircleIcon,
  CommandLineIcon as SolidCommandLineIcon,
  CpuChipIcon as SolidCpuChipIcon,
  DocumentArrowDownIcon as SolidDocumentArrowDownIcon,
  DocumentIcon as SolidDocumentIcon,
  DocumentTextIcon as SolidDocumentTextIcon,
  ExclamationCircleIcon as SolidExclamationCircleIcon,
  ExclamationTriangleIcon as SolidExclamationTriangleIcon,
  EyeIcon as SolidEyeIcon,
  EyeSlashIcon as SolidEyeSlashIcon,
  HomeIcon as SolidHomeIcon,
  InformationCircleIcon as SolidInformationCircleIcon,
  ListBulletIcon as SolidListBulletIcon,
  LockClosedIcon as SolidLockClosedIcon,
  LockOpenIcon as SolidLockOpenIcon,
  MagnifyingGlassIcon as SolidMagnifyingGlassIcon,
  QuestionMarkCircleIcon as SolidQuestionMarkCircleIcon,
  RocketLaunchIcon as SolidRocketLaunchIcon,
  ShieldCheckIcon as SolidShieldCheckIcon,
  SparklesIcon as SolidSparklesIcon,
  WrenchScrewdriverIcon as SolidWrenchScrewdriverIcon,
  XMarkIcon as SolidXMarkIcon,
} from '@heroicons/react/24/solid';

type IconVariant = 'outline' | 'solid';
type IconComponent = React.ComponentType<React.SVGProps<SVGSVGElement>>;

interface IconProps extends React.SVGProps<SVGSVGElement> {
  name: string;
  variant?: IconVariant;
  size?: number;
  disabled?: boolean;
}

const outlineIcons = {
  ArrowLeftIcon: OutlineArrowLeftIcon,
  ArrowUpTrayIcon: OutlineArrowUpTrayIcon,
  Bars3Icon: OutlineBars3Icon,
  BeakerIcon: OutlineBeakerIcon,
  BoltIcon: OutlineBoltIcon,
  ChartBarIcon: OutlineChartBarIcon,
  CheckCircleIcon: OutlineCheckCircleIcon,
  CommandLineIcon: OutlineCommandLineIcon,
  CpuChipIcon: OutlineCpuChipIcon,
  DocumentArrowDownIcon: OutlineDocumentArrowDownIcon,
  DocumentIcon: OutlineDocumentIcon,
  DocumentTextIcon: OutlineDocumentTextIcon,
  ExclamationCircleIcon: OutlineExclamationCircleIcon,
  ExclamationTriangleIcon: OutlineExclamationTriangleIcon,
  EyeIcon: OutlineEyeIcon,
  EyeSlashIcon: OutlineEyeSlashIcon,
  HomeIcon: OutlineHomeIcon,
  InformationCircleIcon: OutlineInformationCircleIcon,
  ListBulletIcon: OutlineListBulletIcon,
  LockClosedIcon: OutlineLockClosedIcon,
  LockOpenIcon: OutlineLockOpenIcon,
  MagnifyingGlassIcon: OutlineMagnifyingGlassIcon,
  QuestionMarkCircleIcon,
  RocketLaunchIcon: OutlineRocketLaunchIcon,
  ShieldCheckIcon: OutlineShieldCheckIcon,
  SparklesIcon: OutlineSparklesIcon,
  WrenchScrewdriverIcon: OutlineWrenchScrewdriverIcon,
  XMarkIcon: OutlineXMarkIcon,
} satisfies Record<string, IconComponent>;

const solidIcons = {
  ArrowLeftIcon: SolidArrowLeftIcon,
  ArrowUpTrayIcon: SolidArrowUpTrayIcon,
  Bars3Icon: SolidBars3Icon,
  BeakerIcon: SolidBeakerIcon,
  BoltIcon: SolidBoltIcon,
  ChartBarIcon: SolidChartBarIcon,
  CheckCircleIcon: SolidCheckCircleIcon,
  CommandLineIcon: SolidCommandLineIcon,
  CpuChipIcon: SolidCpuChipIcon,
  DocumentArrowDownIcon: SolidDocumentArrowDownIcon,
  DocumentIcon: SolidDocumentIcon,
  DocumentTextIcon: SolidDocumentTextIcon,
  ExclamationCircleIcon: SolidExclamationCircleIcon,
  ExclamationTriangleIcon: SolidExclamationTriangleIcon,
  EyeIcon: SolidEyeIcon,
  EyeSlashIcon: SolidEyeSlashIcon,
  HomeIcon: SolidHomeIcon,
  InformationCircleIcon: SolidInformationCircleIcon,
  ListBulletIcon: SolidListBulletIcon,
  LockClosedIcon: SolidLockClosedIcon,
  LockOpenIcon: SolidLockOpenIcon,
  MagnifyingGlassIcon: SolidMagnifyingGlassIcon,
  QuestionMarkCircleIcon: SolidQuestionMarkCircleIcon,
  RocketLaunchIcon: SolidRocketLaunchIcon,
  ShieldCheckIcon: SolidShieldCheckIcon,
  SparklesIcon: SolidSparklesIcon,
  WrenchScrewdriverIcon: SolidWrenchScrewdriverIcon,
  XMarkIcon: SolidXMarkIcon,
} satisfies Record<string, IconComponent>;

function Icon({
  name,
  variant = 'outline',
  size = 24,
  className = '',
  onClick,
  disabled = false,
  ...props
}: IconProps) {
  const iconSet = variant === 'solid' ? solidIcons : outlineIcons;
  const iconKey = name as keyof typeof outlineIcons;
  const IconComponent = iconSet[iconKey] ?? outlineIcons[iconKey] ?? QuestionMarkCircleIcon;
  const isFallback = !(iconKey in iconSet) && !(iconKey in outlineIcons);

  const stateClass = disabled
    ? 'opacity-50 cursor-not-allowed'
    : onClick
      ? 'cursor-pointer hover:opacity-80'
      : '';
  const fallbackClass = isFallback ? 'text-gray-400' : '';
  const resolvedClassName = [fallbackClass, stateClass, className]
    .filter(Boolean)
    .join(' ');

  return (
    <IconComponent
      width={size}
      height={size}
      className={resolvedClassName}
      onClick={disabled ? undefined : onClick}
      {...props}
    />
  );
}

export default Icon;
