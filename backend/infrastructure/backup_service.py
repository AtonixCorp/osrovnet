"""
Backup and Recovery Service
"""
import logging
import os
import shutil
import subprocess
import gzip
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from django.utils import timezone
from django.conf import settings
from django.core.management import call_command
from django.db import transaction
from .models import BackupJob, BackupExecution

logger = logging.getLogger(__name__)

class BackupService:
    """Service for managing backups and recovery operations"""
    
    def __init__(self):
        self.backup_root = getattr(settings, 'BACKUP_ROOT', '/var/backups/osrovnet')
        self.ensure_backup_directory()
    
    def ensure_backup_directory(self):
        """Ensure backup directory exists"""
        try:
            os.makedirs(self.backup_root, exist_ok=True)
            logger.info(f"Backup directory ensured: {self.backup_root}")
        except Exception as e:
            logger.error(f"Error creating backup directory: {e}")
    
    def execute_backup(self, backup_job: BackupJob) -> BackupExecution:
        """Execute a backup job"""
        execution = BackupExecution.objects.create(
            backup_job=backup_job,
            status='started'
        )
        
        try:
            logger.info(f"Starting backup job: {backup_job.name}")
            execution.status = 'running'
            execution.save()
            
            # Execute backup based on type
            if backup_job.backup_type == 'database':
                self._backup_database(backup_job, execution)
            elif backup_job.backup_type == 'files':
                self._backup_files(backup_job, execution)
            elif backup_job.backup_type == 'configuration':
                self._backup_configuration(backup_job, execution)
            elif backup_job.backup_type == 'logs':
                self._backup_logs(backup_job, execution)
            elif backup_job.backup_type == 'full_system':
                self._backup_full_system(backup_job, execution)
            
            execution.status = 'completed'
            execution.completed_at = timezone.now()
            execution.duration = execution.completed_at - execution.started_at
            
            # Update backup job
            backup_job.last_run = timezone.now()
            backup_job.save()
            
            logger.info(f"Backup job completed: {backup_job.name}")
            
        except Exception as e:
            execution.status = 'failed'
            execution.error_message = str(e)
            execution.completed_at = timezone.now()
            execution.duration = execution.completed_at - execution.started_at
            logger.error(f"Backup job failed: {backup_job.name} - {e}")
        
        execution.save()
        return execution
    
    def _backup_database(self, backup_job: BackupJob, execution: BackupExecution):
        """Backup database"""
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f"database_backup_{timestamp}.sql"
        backup_path = os.path.join(self.backup_root, 'database', filename)
        
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        try:
            # Use Django's dumpdata command for SQLite
            with open(backup_path, 'w') as f:
                call_command('dumpdata', stdout=f, indent=2)
            
            # Compress if enabled
            if backup_job.compression_enabled:
                compressed_path = f"{backup_path}.gz"
                with open(backup_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(backup_path)
                backup_path = compressed_path
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Update execution
            execution.backup_path = backup_path
            execution.backup_size = os.path.getsize(backup_path)
            execution.checksum = checksum
            execution.logs += f"Database backup created: {backup_path}\n"
            
        except Exception as e:
            raise Exception(f"Database backup failed: {e}")
    
    def _backup_files(self, backup_job: BackupJob, execution: BackupExecution):
        """Backup files and directories"""
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"files_backup_{timestamp}"
        backup_path = os.path.join(self.backup_root, 'files', backup_name)
        
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        try:
            source_path = backup_job.source_path
            
            if backup_job.compression_enabled:
                # Create tar.gz archive
                archive_path = f"{backup_path}.tar.gz"
                cmd = ['tar', 'czf', archive_path, '-C', os.path.dirname(source_path), os.path.basename(source_path)]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                backup_path = archive_path
            else:
                # Copy directory
                if os.path.isdir(source_path):
                    shutil.copytree(source_path, backup_path)
                else:
                    shutil.copy2(source_path, backup_path)
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Count files
            files_count = self._count_files(backup_path if not backup_job.compression_enabled else source_path)
            
            # Update execution
            execution.backup_path = backup_path
            execution.backup_size = os.path.getsize(backup_path) if os.path.isfile(backup_path) else self._get_directory_size(backup_path)
            execution.files_count = files_count
            execution.checksum = checksum
            execution.logs += f"Files backup created: {backup_path}\n"
            
        except Exception as e:
            raise Exception(f"Files backup failed: {e}")
    
    def _backup_configuration(self, backup_job: BackupJob, execution: BackupExecution):
        """Backup configuration files"""
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"config_backup_{timestamp}"
        backup_path = os.path.join(self.backup_root, 'configuration', backup_name)
        
        os.makedirs(backup_path, exist_ok=True)
        
        try:
            # Define configuration files to backup
            config_files = [
                'backend/osrovnet/settings.py',
                'docker-compose.yml',
                'docker-compose.dev.yml',
                '.env',
                'requirements.txt',
                'package.json'
            ]
            
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            files_backed_up = 0
            
            for config_file in config_files:
                source = os.path.join(project_root, config_file)
                if os.path.exists(source):
                    dest = os.path.join(backup_path, config_file)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(source, dest)
                    files_backed_up += 1
            
            # Create archive if compression is enabled
            if backup_job.compression_enabled:
                archive_path = f"{backup_path}.tar.gz"
                cmd = ['tar', 'czf', archive_path, '-C', os.path.dirname(backup_path), os.path.basename(backup_path)]
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                shutil.rmtree(backup_path)
                backup_path = archive_path
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Update execution
            execution.backup_path = backup_path
            execution.backup_size = os.path.getsize(backup_path) if os.path.isfile(backup_path) else self._get_directory_size(backup_path)
            execution.files_count = files_backed_up
            execution.checksum = checksum
            execution.logs += f"Configuration backup created: {backup_path}\n"
            
        except Exception as e:
            raise Exception(f"Configuration backup failed: {e}")
    
    def _backup_logs(self, backup_job: BackupJob, execution: BackupExecution):
        """Backup log files"""
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"logs_backup_{timestamp}"
        backup_path = os.path.join(self.backup_root, 'logs', backup_name)
        
        os.makedirs(backup_path, exist_ok=True)
        
        try:
            # Define log directories to backup
            log_paths = [
                'backend/logs',
                '/var/log/osrovnet'  # System logs if they exist
            ]
            
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            files_backed_up = 0
            
            for log_path in log_paths:
                if not os.path.isabs(log_path):
                    source = os.path.join(project_root, log_path)
                else:
                    source = log_path
                    
                if os.path.exists(source):
                    dest = os.path.join(backup_path, os.path.basename(source))
                    if os.path.isdir(source):
                        shutil.copytree(source, dest)
                        files_backed_up += self._count_files(dest)
                    else:
                        shutil.copy2(source, dest)
                        files_backed_up += 1
            
            # Create archive if compression is enabled
            if backup_job.compression_enabled:
                archive_path = f"{backup_path}.tar.gz"
                cmd = ['tar', 'czf', archive_path, '-C', os.path.dirname(backup_path), os.path.basename(backup_path)]
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                shutil.rmtree(backup_path)
                backup_path = archive_path
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Update execution
            execution.backup_path = backup_path
            execution.backup_size = os.path.getsize(backup_path) if os.path.isfile(backup_path) else self._get_directory_size(backup_path)
            execution.files_count = files_backed_up
            execution.checksum = checksum
            execution.logs += f"Logs backup created: {backup_path}\n"
            
        except Exception as e:
            raise Exception(f"Logs backup failed: {e}")
    
    def _backup_full_system(self, backup_job: BackupJob, execution: BackupExecution):
        """Perform full system backup"""
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"full_system_backup_{timestamp}"
        backup_path = os.path.join(self.backup_root, 'full_system', backup_name)
        
        os.makedirs(backup_path, exist_ok=True)
        
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            
            # Backup database
            db_execution = BackupExecution()
            self._backup_database(backup_job, db_execution)
            shutil.copy2(db_execution.backup_path, os.path.join(backup_path, 'database.sql.gz'))
            
            # Backup configuration
            config_execution = BackupExecution()
            self._backup_configuration(backup_job, config_execution)
            shutil.copy2(config_execution.backup_path, os.path.join(backup_path, 'configuration.tar.gz'))
            
            # Backup application code (excluding node_modules, __pycache__, etc.)
            app_backup_path = os.path.join(backup_path, 'application')
            os.makedirs(app_backup_path, exist_ok=True)
            
            exclude_patterns = [
                'node_modules',
                '__pycache__',
                '*.pyc',
                '.git',
                'venv',
                'env',
                '.env',
                'logs',
                'backups'
            ]
            
            # Use rsync for efficient copying with exclusions
            rsync_cmd = ['rsync', '-av'] + [f'--exclude={pattern}' for pattern in exclude_patterns]
            rsync_cmd.extend([f'{project_root}/', app_backup_path])
            
            subprocess.run(rsync_cmd, capture_output=True, text=True, check=True)
            
            # Create final archive
            archive_path = f"{backup_path}.tar.gz"
            cmd = ['tar', 'czf', archive_path, '-C', os.path.dirname(backup_path), os.path.basename(backup_path)]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            shutil.rmtree(backup_path)
            backup_path = archive_path
            
            # Calculate checksum
            checksum = self._calculate_checksum(backup_path)
            
            # Update execution
            execution.backup_path = backup_path
            execution.backup_size = os.path.getsize(backup_path)
            execution.checksum = checksum
            execution.logs += f"Full system backup created: {backup_path}\n"
            
        except Exception as e:
            raise Exception(f"Full system backup failed: {e}")
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA-256 checksum of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating checksum for {file_path}: {e}")
            return ""
    
    def _count_files(self, path: str) -> int:
        """Count files in a directory recursively"""
        if os.path.isfile(path):
            return 1
        
        count = 0
        for root, dirs, files in os.walk(path):
            count += len(files)
        return count
    
    def _get_directory_size(self, path: str) -> int:
        """Get total size of directory in bytes"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
        return total_size
    
    def cleanup_old_backups(self, backup_job: BackupJob):
        """Clean up old backups based on retention policy"""
        try:
            retention_date = timezone.now() - timedelta(days=backup_job.retention_days)
            
            old_executions = BackupExecution.objects.filter(
                backup_job=backup_job,
                started_at__lt=retention_date,
                status='completed'
            )
            
            for execution in old_executions:
                if execution.backup_path and os.path.exists(execution.backup_path):
                    try:
                        if os.path.isfile(execution.backup_path):
                            os.remove(execution.backup_path)
                        else:
                            shutil.rmtree(execution.backup_path)
                        logger.info(f"Cleaned up old backup: {execution.backup_path}")
                    except Exception as e:
                        logger.error(f"Error cleaning up backup {execution.backup_path}: {e}")
                
                execution.delete()
                
        except Exception as e:
            logger.error(f"Error cleaning up old backups for {backup_job.name}: {e}")
    
    def restore_backup(self, execution: BackupExecution, restore_path: str = None) -> bool:
        """Restore from a backup"""
        try:
            if not execution.backup_path or not os.path.exists(execution.backup_path):
                raise Exception("Backup file not found")
            
            backup_job = execution.backup_job
            
            if backup_job.backup_type == 'database':
                return self._restore_database(execution)
            elif backup_job.backup_type == 'files':
                return self._restore_files(execution, restore_path)
            elif backup_job.backup_type == 'configuration':
                return self._restore_configuration(execution)
            else:
                raise Exception(f"Restore not implemented for backup type: {backup_job.backup_type}")
                
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def _restore_database(self, execution: BackupExecution) -> bool:
        """Restore database from backup"""
        try:
            backup_path = execution.backup_path
            
            # Handle compressed backups
            if backup_path.endswith('.gz'):
                temp_path = backup_path[:-3]  # Remove .gz extension
                with gzip.open(backup_path, 'rb') as f_in:
                    with open(temp_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                backup_path = temp_path
            
            # Use Django's loaddata command
            call_command('loaddata', backup_path)
            
            # Clean up temp file if created
            if backup_path != execution.backup_path:
                os.remove(backup_path)
            
            logger.info(f"Database restored from: {execution.backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Database restore failed: {e}")
            return False
    
    def _restore_files(self, execution: BackupExecution, restore_path: str = None) -> bool:
        """Restore files from backup"""
        try:
            backup_path = execution.backup_path
            
            if not restore_path:
                restore_path = execution.backup_job.source_path
            
            if backup_path.endswith('.tar.gz'):
                # Extract archive
                cmd = ['tar', 'xzf', backup_path, '-C', os.path.dirname(restore_path)]
                subprocess.run(cmd, capture_output=True, text=True, check=True)
            else:
                # Copy directory or file
                if os.path.isdir(backup_path):
                    if os.path.exists(restore_path):
                        shutil.rmtree(restore_path)
                    shutil.copytree(backup_path, restore_path)
                else:
                    shutil.copy2(backup_path, restore_path)
            
            logger.info(f"Files restored from: {backup_path} to: {restore_path}")
            return True
            
        except Exception as e:
            logger.error(f"Files restore failed: {e}")
            return False
    
    def _restore_configuration(self, execution: BackupExecution) -> bool:
        """Restore configuration from backup"""
        try:
            backup_path = execution.backup_path
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            
            if backup_path.endswith('.tar.gz'):
                # Extract archive to temporary location
                temp_dir = f"/tmp/config_restore_{int(timezone.now().timestamp())}"
                os.makedirs(temp_dir, exist_ok=True)
                
                cmd = ['tar', 'xzf', backup_path, '-C', temp_dir]
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                
                # Copy files to project root
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        src = os.path.join(root, file)
                        rel_path = os.path.relpath(src, temp_dir)
                        dest = os.path.join(project_root, rel_path)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        shutil.copy2(src, dest)
                
                # Clean up temp directory
                shutil.rmtree(temp_dir)
            
            logger.info(f"Configuration restored from: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Configuration restore failed: {e}")
            return False
    
    def verify_backup(self, execution: BackupExecution) -> bool:
        """Verify backup integrity"""
        try:
            if not execution.backup_path or not os.path.exists(execution.backup_path):
                return False
            
            # Verify checksum if available
            if execution.checksum:
                current_checksum = self._calculate_checksum(execution.backup_path)
                if current_checksum != execution.checksum:
                    logger.error(f"Checksum mismatch for backup: {execution.backup_path}")
                    return False
            
            # Additional verification based on backup type
            backup_job = execution.backup_job
            
            if backup_job.backup_type == 'database' and execution.backup_path.endswith('.gz'):
                # Test gzip file integrity
                try:
                    with gzip.open(execution.backup_path, 'rb') as f:
                        f.read(1024)  # Try to read some data
                except Exception:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return False

# Global instance
backup_service = BackupService()